import { DeplyzeError, ErrorCode } from '@deplyze/core';
import type { DependencyKind } from '@deplyze/core';
import { parse as parseYaml } from 'yaml';
import type { LockfileParser, ParsedLockfile, ImportedRef, ResolvedPackage } from './model.js';

interface PnpmDependencyRef {
  specifier?: string;
  version?: string;
}

interface PnpmPackageEntry {
  resolution?: { integrity?: string; tarball?: string };
  engines?: Record<string, string>;
  deprecated?: string | boolean;
  dev?: boolean;
  optional?: boolean;
  hasBin?: boolean;
  requiresBuild?: boolean;
  dependencies?: Record<string, string | PnpmDependencyRef>;
  optionalDependencies?: Record<string, string | PnpmDependencyRef>;
  peerDependencies?: Record<string, string | PnpmDependencyRef>;
  license?: string;
}

interface PnpmLockfile {
  lockfileVersion?: string | number;
  importers?: Record<string, Record<string, Record<string, PnpmDependencyRef>>>;
  dependencies?: Record<string, PnpmDependencyRef>;
  devDependencies?: Record<string, PnpmDependencyRef>;
  optionalDependencies?: Record<string, PnpmDependencyRef>;
  packages?: Record<string, PnpmPackageEntry>;
  snapshots?: Record<string, PnpmPackageEntry>;
}

/** Strip pnpm's peer-dependency suffix from a version or key. */
function stripPeerSuffix(value: string): string {
  const paren = value.indexOf('(');
  if (paren !== -1) return value.slice(0, paren);
  // pnpm 5/6 used `_` to separate peer context; semver never contains `_`.
  const underscore = value.indexOf('_');
  if (underscore !== -1 && !value.startsWith('link:')) return value.slice(0, underscore);
  return value;
}

/**
 * Parse a pnpm package key into name and version.
 *
 * Supported shapes:
 *   `lodash@4.17.21`              (v6/v9)
 *   `@scope/name@1.0.0`           (v6/v9)
 *   `/lodash@4.17.21`             (v6 with leading slash)
 *   `/lodash/4.17.21`             (v5)
 *   `/@scope/name/1.0.0`          (v5, scoped)
 *   `name@1.0.0(peer@2.0.0)`      (peer-suffixed)
 */
export function parsePnpmPackageKey(key: string): { name: string; version: string } | undefined {
  const cleaned = key.startsWith('/') ? key.slice(1) : key;
  const withoutPeer = stripPeerSuffix(cleaned);
  const at = withoutPeer.lastIndexOf('@');
  if (at > 0) {
    const name = withoutPeer.slice(0, at);
    const version = withoutPeer.slice(at + 1);
    if (name && version) return { name, version };
  }
  const slash = withoutPeer.lastIndexOf('/');
  if (slash > 0) {
    const name = withoutPeer.slice(0, slash);
    const version = withoutPeer.slice(slash + 1);
    if (name && version) return { name, version };
  }
  return undefined;
}

function toSpecMap(source: Record<string, string | PnpmDependencyRef> | undefined): Record<string, string> {
  const result: Record<string, string> = {};
  if (!source) return result;
  for (const [name, value] of Object.entries(source)) {
    if (typeof value === 'string') {
      result[name] = stripPeerSuffix(normalizeLegacySpec(value));
    } else if (value && typeof value === 'object' && typeof value.version === 'string') {
      result[name] = stripPeerSuffix(normalizeLegacySpec(value.version));
    }
  }
  return result;
}

/** Convert pnpm v5's `/name/1.2.3` and `/@scope/name/1.2.3` specs to versions. */
function normalizeLegacySpec(value: string): string {
  if (!value.startsWith('/')) return value;
  const legacy = value.match(/^\/(?:@[^/]+\/)?[^/]+\/(.+)$/);
  return legacy?.[1] ?? value.slice(1).replace(/\//g, '@');
}

function addImporter(
  imports: ImportedRef[],
  importer: string,
  section: string,
  deps: Record<string, PnpmDependencyRef> | undefined,
): void {
  const kindBySection: Record<string, DependencyKind> = {
    dependencies: 'prod',
    devDependencies: 'dev',
    optionalDependencies: 'optional',
    peerDependencies: 'peer',
  };
  const kind = kindBySection[section];
  if (!kind || !deps) return;
  for (const [name, ref] of Object.entries(deps)) {
    if (!ref || typeof ref !== 'object') continue;
    const range = ref.specifier ?? ref.version ?? '*';
    const entry: ImportedRef = { importer, name, range, kind };
    if (ref.version && !ref.version.startsWith('link:') && !ref.version.startsWith('workspace:')) {
      entry.resolvedVersion = stripPeerSuffix(ref.version);
    }
    imports.push(entry);
  }
}

export const pnpmLockParser: LockfileParser = {
  manager: 'pnpm',
  filename: 'pnpm-lock.yaml',
  detect: (filename) => filename === 'pnpm-lock.yaml',
  parse(raw, filename): ParsedLockfile {
    let data: PnpmLockfile;
    try {
      data = parseYaml(raw) as PnpmLockfile;
    } catch (error) {
      throw new DeplyzeError(
        ErrorCode.DEPLYZE_E_LOCKFILE_PARSE,
        `Could not parse ${filename}: invalid YAML.`,
        {
          hint: 'Regenerate the lockfile with `pnpm install --lockfile-only`.',
          cause: error,
        },
      );
    }
    if (!data || typeof data !== 'object') {
      throw new DeplyzeError(
        ErrorCode.DEPLYZE_E_LOCKFILE_PARSE,
        `Could not parse ${filename}: empty lockfile.`,
      );
    }

    const formatVersion = data.lockfileVersion !== undefined ? String(data.lockfileVersion) : undefined;
    const major = Number.parseInt((formatVersion ?? '0').split('.')[0] ?? '0', 10);
    if (major > 9) {
      throw new DeplyzeError(
        ErrorCode.DEPLYZE_E_LOCKFILE_UNSUPPORTED,
        `Unsupported pnpm lockfile version: ${formatVersion}.`,
        { hint: 'Upgrade Deplyze to a release that supports this lockfile format.' },
      );
    }

    const packages: ResolvedPackage[] = [];
    const imports: ImportedRef[] = [];
    const notes: string[] = [];

    // Dependency edges live in `snapshots` for v9, `packages` for v5/v6.
    const snapshotSource = data.snapshots ?? data.packages ?? {};

    for (const [key, entry] of Object.entries(data.packages ?? {})) {
      const parsed = parsePnpmPackageKey(key);
      if (!parsed) {
        notes.push(`Skipped unrecognized pnpm package key: ${key}`);
        continue;
      }
      const snapshot = snapshotSource[key];
      const pkg: ResolvedPackage = {
        name: parsed.name,
        version: parsed.version,
        ecosystem: 'npm',
        locator: key,
        dependencies: toSpecMap((snapshot ?? entry).dependencies),
        optionalDependencies: toSpecMap((snapshot ?? entry).optionalDependencies),
        peerDependencies: toSpecMap((snapshot ?? entry).peerDependencies),
      };
      const integrity = entry.resolution?.integrity;
      if (integrity) pkg.integrity = integrity;
      if (entry.resolution?.tarball) pkg.resolved = entry.resolution.tarball;
      if (entry.license) pkg.license = entry.license;
      if (entry.engines) pkg.engines = entry.engines;
      if (entry.deprecated) pkg.deprecated = entry.deprecated;
      if (entry.dev) pkg.dev = true;
      if (entry.optional) pkg.optional = true;
      packages.push(pkg);
    }

    if (data.importers && Object.keys(data.importers).length > 0) {
      for (const [importer, sections] of Object.entries(data.importers)) {
        for (const [section, deps] of Object.entries(sections ?? {})) {
          addImporter(imports, importer, section, deps as Record<string, PnpmDependencyRef>);
        }
      }
    } else {
      // Pre-v6 lockfiles keep the root importer at the top level.
      addImporter(imports, '.', 'dependencies', data.dependencies);
      addImporter(imports, '.', 'devDependencies', data.devDependencies);
      addImporter(imports, '.', 'optionalDependencies', data.optionalDependencies);
    }

    if (packages.length === 0) {
      notes.push('pnpm lockfile contained no packages; Deplyze used manifest ranges only.');
    }

    return { manager: 'pnpm', formatVersion, packages, imports, notes };
  },
};
