import { DeplyzeError, ErrorCode } from '@deplyze/core';
import type { LockfileParser, ParsedLockfile, ImportedRef, ResolvedPackage } from './model.js';

interface NpmLockDependency {
  version?: string;
  resolved?: string;
  integrity?: string;
  dev?: boolean;
  optional?: boolean;
  peer?: boolean;
  license?: string;
  deprecated?: boolean | string;
  dependencies?: Record<string, unknown>;
  devDependencies?: Record<string, unknown>;
  optionalDependencies?: Record<string, unknown>;
  peerDependencies?: Record<string, unknown>;
  requires?: Record<string, string>;
  engines?: Record<string, string>;
  hasInstallScript?: boolean;
}

interface NpmLockFile {
  name?: string;
  version?: string;
  lockfileVersion?: number;
  packages?: Record<string, NpmLockDependency & { name?: string }>;
  dependencies?: Record<string, NpmLockDependency>;
}

/** Strip npm's install path prefix to recover the package name. */
function nameFromPath(location: string): string | undefined {
  const marker = 'node_modules/';
  const index = location.lastIndexOf(marker);
  if (index === -1) return undefined;
  const rest = location.slice(index + marker.length);
  if (rest.startsWith('@')) {
    const [scope, name] = rest.split('/');
    if (!scope || !name) return undefined;
    return `${scope}/${name}`;
  }
  return rest.split('/')[0];
}

function mapsOf(source: Record<string, unknown> | undefined): Record<string, string> {
  const result: Record<string, string> = {};
  if (!source) return result;
  for (const [key, value] of Object.entries(source)) {
    if (typeof value === 'string') result[key] = value;
    else if (
      value &&
      typeof value === 'object' &&
      typeof (value as { version?: unknown }).version === 'string'
    ) {
      result[key] = (value as { version: string }).version;
    }
  }
  return result;
}

function licenseOfDependency(dep: NpmLockDependency): string | undefined {
  return typeof dep.license === 'string' && dep.license.length > 0 ? dep.license : undefined;
}

export const npmLockParser: LockfileParser = {
  manager: 'npm',
  filename: 'package-lock.json',
  detect: (filename) => filename === 'package-lock.json',
  parse(raw, filename): ParsedLockfile {
    let data: NpmLockFile;
    try {
      data = JSON.parse(raw) as NpmLockFile;
    } catch (error) {
      throw new DeplyzeError(
        ErrorCode.DEPLYZE_E_LOCKFILE_PARSE,
        `Could not parse ${filename}: invalid JSON.`,
        {
          hint: 'Regenerate the lockfile with `npm install --package-lock-only`.',
          cause: error,
        },
      );
    }
    const formatVersion = data.lockfileVersion ? String(data.lockfileVersion) : undefined;
    const packages: ResolvedPackage[] = [];
    const imports: ImportedRef[] = [];
    const notes: string[] = [];

    if (data.packages && Object.keys(data.packages).length > 0) {
      for (const [location, entry] of Object.entries(data.packages)) {
        if (location === '') {
          // Root project record. Turn its dependency maps into direct imports.
          for (const [name, range] of Object.entries(entry.dependencies ?? {})) {
            if (typeof range === 'string') imports.push({ importer: '.', name, range, kind: 'prod' });
          }
          for (const [name, range] of Object.entries(entry.devDependencies ?? {})) {
            if (typeof range === 'string') imports.push({ importer: '.', name, range, kind: 'dev' });
          }
          for (const [name, range] of Object.entries(entry.optionalDependencies ?? {})) {
            if (typeof range === 'string') imports.push({ importer: '.', name, range, kind: 'optional' });
          }
          for (const [name, range] of Object.entries(entry.peerDependencies ?? {})) {
            if (typeof range === 'string') imports.push({ importer: '.', name, range, kind: 'peer' });
          }
          continue;
        }
        const name = entry.name ?? nameFromPath(location);
        if (!name || !entry.version) continue;
        const pkg: ResolvedPackage = {
          name,
          version: entry.version,
          ecosystem: 'npm',
          locator: location,
          dependencies: mapsOf(entry.dependencies ?? entry.requires),
          optionalDependencies: mapsOf(entry.optionalDependencies),
          peerDependencies: mapsOf(entry.peerDependencies),
        };
        if (entry.resolved) pkg.resolved = entry.resolved;
        if (entry.integrity) pkg.integrity = entry.integrity;
        const license = licenseOfDependency(entry);
        if (license) pkg.license = license;
        if (entry.deprecated) pkg.deprecated = entry.deprecated;
        if (entry.engines) pkg.engines = entry.engines;
        if (entry.dev) pkg.dev = true;
        if (entry.optional) pkg.optional = true;
        if (entry.peer) pkg.peer = true;
        packages.push(pkg);
      }
    } else if (data.dependencies) {
      // npm v1 / v2 fallback: a nested dependency tree without install paths.
      if (formatVersion && Number(formatVersion) >= 2) {
        notes.push('package-lock.json had no `packages` map; fell back to the legacy dependency tree.');
      }
      const walk = (deps: Record<string, NpmLockDependency>, importer: string, depth: number): void => {
        if (!deps || typeof deps !== 'object') return;
        if (depth > 100) return;
        for (const [name, entry] of Object.entries(deps)) {
          if (!entry.version) continue;
          const pkg: ResolvedPackage = {
            name,
            version: entry.version,
            ecosystem: 'npm',
            locator: `${importer}/${name}@${entry.version}`,
            dependencies: mapsOf(entry.requires ?? entry.dependencies),
          };
          if (entry.resolved) pkg.resolved = entry.resolved;
          if (entry.integrity) pkg.integrity = entry.integrity;
          if (entry.dev) pkg.dev = true;
          if (entry.optional) pkg.optional = true;
          if (entry.deprecated) pkg.deprecated = entry.deprecated;
          packages.push(pkg);
          if (importer === '.' && depth === 0) {
            imports.push({ importer: '.', name, range: entry.version, kind: entry.dev ? 'dev' : 'prod' });
          }
          if (entry.dependencies && typeof entry.dependencies === 'object') {
            walk(entry.dependencies as Record<string, NpmLockDependency>, `${importer}/${name}`, depth + 1);
          }
        }
      };
      walk(data.dependencies, '.', 0);
    }

    if (packages.length === 0 && imports.length === 0) {
      notes.push('Lockfile contained no resolvable packages; Deplyze used manifest ranges only.');
    }

    return { manager: 'npm', formatVersion, packages, imports, notes };
  },
};
