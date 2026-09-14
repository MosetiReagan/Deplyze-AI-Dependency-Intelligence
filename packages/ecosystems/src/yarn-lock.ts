import { DeplyzeError, ErrorCode } from '@deplyze/core';
import { parse as parseYaml } from 'yaml';
import type { LockfileParser, ParsedLockfile, ImportedRef, ResolvedPackage } from './model.js';

/** Split `name@range` (v1 descriptors) into name and range. */
function parseDescriptor(descriptor: string): { name: string; range: string } | undefined {
  const clean = descriptor.replace(/^"|"$/g, '').trim();
  if (clean.length === 0) return undefined;
  const at = clean.lastIndexOf('@');
  if (at <= 0) return undefined;
  return { name: clean.slice(0, at), range: clean.slice(at + 1) };
}

/**
 * Parse a v1 dependency entry such as `"@babel/highlight" "^7.10.4"` or
 * `lodash "^4.17.21"`. Unlike header descriptors these are two tokens, so we
 * cannot reuse `parseDescriptor` (a leading `@` would look like the range
 * separator).
 */
function parseV1DependencyEntry(line: string): { name: string; range: string } | undefined {
  const match = line.trim().match(/^(?:"([^"]+)"|(\S+))\s+(?:"([^"]+)"|(\S+))$/);
  if (!match) return undefined;
  const name = match[1] ?? match[2];
  const range = match[3] ?? match[4];
  if (!name || !range) return undefined;
  return { name, range };
}

function parseV1(raw: string): ParsedLockfile {
  const packages: ResolvedPackage[] = [];
  const imports: ImportedRef[] = [];
  const notes: string[] = [];
  const seen = new Set<string>();

  const lines = raw.split(/\r?\n/);
  let descriptors: string[] = [];
  let inBody = false;
  let current: ResolvedPackage | undefined;
  let currentDescriptor: string | undefined;
  let section: 'dependencies' | 'optionalDependencies' | null = null;

  const flush = (): void => {
    if (current && currentDescriptor) {
      const descriptor = parseDescriptor(currentDescriptor);
      if (descriptor && !seen.has(`${descriptor.name}@${current.version}`)) {
        seen.add(`${descriptor.name}@${current.version}`);
        packages.push(current);
      }
    }
    current = undefined;
    currentDescriptor = undefined;
    section = null;
  };

  for (const line of lines) {
    if (line.trim().length === 0) continue;
    if (line.startsWith('#')) continue;
    const indented = /^\s/.test(line);

    if (!indented) {
      flush();
      inBody = true;
      const header = line.replace(/:\s*$/, '');
      descriptors = header
        .split(/,\s*/)
        .map((part) => part.trim())
        .filter((part) => part.length > 0);
      const first = descriptors[0];
      if (!first) continue;
      const parsed = parseDescriptor(first);
      if (!parsed) continue;
      current = { name: parsed.name, version: '', ecosystem: 'npm', dependencies: {} };
      currentDescriptor = first;
      continue;
    }

    if (!inBody || !current) continue;
    const trimmed = line.trim();

    if (
      /^(version|resolved|integrity|license|deprecated)\s/.test(trimmed) &&
      !/^(version|resolved|integrity|license|deprecated):/.test(trimmed)
    ) {
      const match = trimmed.match(/^(\w+)\s+(.*)$/);
      if (match) {
        const [, key, valueRaw] = match;
        const value = (valueRaw ?? '').replace(/^"|"$/g, '');
        if (key === 'version') current.version = value;
        else if (key === 'resolved') current.resolved = value;
        else if (key === 'integrity') current.integrity = value;
        else if (key === 'license') current.license = value;
        else if (key === 'deprecated') current.deprecated = value;
      }
      continue;
    }

    if (/^(version|resolved|integrity|license|deprecated):/.test(trimmed)) {
      const match = trimmed.match(/^(\w+):\s*(.*)$/);
      if (match) {
        const [, key, valueRaw] = match;
        const value = (valueRaw ?? '').replace(/^"|"$/g, '');
        if (key === 'version') current.version = value;
        else if (key === 'resolved') current.resolved = value;
        else if (key === 'integrity') current.integrity = value;
        else if (key === 'license') current.license = value;
        else if (key === 'deprecated') current.deprecated = value;
      }
      continue;
    }

    if (/^dependencies:\s*$/.test(trimmed)) {
      section = 'dependencies';
      continue;
    }
    if (/^optionalDependencies:\s*$/.test(trimmed)) {
      section = 'optionalDependencies';
      continue;
    }
    // Any other `key:` block header (e.g. `peerDependencies:`) ends dependency capture.
    if (/^\w[\w-]*:\s*$/.test(trimmed)) {
      section = null;
      continue;
    }

    if (section && /^\s+\S/.test(line)) {
      const depParsed = parseV1DependencyEntry(trimmed);
      if (depParsed && current) {
        const target =
          section === 'dependencies' ? (current.dependencies ??= {}) : (current.optionalDependencies ??= {});
        target[depParsed.name] = depParsed.range;
      }
    }
  }
  flush();

  return { manager: 'yarn', formatVersion: '1', packages, imports, notes };
}

interface BerryEntry {
  version?: string;
  resolution?: string;
  dependencies?: Record<string, string>;
  peerDependencies?: Record<string, string>;
  checksum?: string;
  conditions?: string;
}

function parseBerry(raw: string, filename: string): ParsedLockfile {
  let data: Record<string, BerryEntry | undefined>;
  try {
    data = parseYaml(raw) as Record<string, BerryEntry | undefined>;
  } catch (error) {
    throw new DeplyzeError(ErrorCode.DEPLYZE_E_LOCKFILE_PARSE, `Could not parse ${filename}: invalid YAML.`, {
      cause: error,
      hint: 'Regenerate the lockfile with `yarn install`.',
    });
  }
  const packages: ResolvedPackage[] = [];
  const imports: ImportedRef[] = [];
  const notes: string[] = [];
  const metadata = data.__metadata as unknown as { version?: number } | undefined;
  const seen = new Set<string>();

  for (const [key, entry] of Object.entries(data)) {
    if (key === '__metadata' || !entry) continue;
    if (key.includes('@workspace:')) continue;
    if (typeof entry !== 'object') continue;

    const resolution = typeof entry.resolution === 'string' ? entry.resolution : undefined;
    const version = entry.version ?? (resolution ? resolution.split('@').pop() : undefined);
    if (!version) continue;

    const descriptor = key.split(/,\s*/)[0]?.replace(/^"|"$/g, '') ?? '';
    const parsedDescriptor = parseDescriptor(descriptor);
    const name = resolution
      ? resolution.slice(0, resolution.lastIndexOf('@')).replace(/@npm$/, '')
      : parsedDescriptor?.name;
    if (!name) continue;
    const dedupeKey = `${name}@${version}`;
    if (seen.has(dedupeKey)) continue;
    seen.add(dedupeKey);

    const resolvedDependencies: Record<string, string> = {};
    for (const [depName, depRange] of Object.entries(entry.dependencies ?? {})) {
      resolvedDependencies[depName] = String(depRange)
        .replace(/^npm:/, '')
        .replace(/^workspace:/, '');
    }
    const pkg: ResolvedPackage = {
      name,
      version,
      ecosystem: 'npm',
      locator: key,
    };
    if (Object.keys(resolvedDependencies).length > 0) pkg.dependencies = resolvedDependencies;
    if (entry.checksum) pkg.integrity = entry.checksum;
    packages.push(pkg);
  }

  return {
    manager: 'yarn',
    formatVersion: metadata?.version ? String(metadata.version) : undefined,
    packages,
    imports,
    notes,
  };
}

export const yarnLockParser: LockfileParser = {
  manager: 'yarn',
  filename: 'yarn.lock',
  detect: (filename) => filename === 'yarn.lock' || filename.endsWith('/yarn.lock'),
  parse(raw, filename): ParsedLockfile {
    if (/^__metadata:/m.test(raw) || /^\s{2}version:\s*\d+\s*$/m.test(raw)) {
      return parseBerry(raw, filename);
    }
    return parseV1(raw);
  },
};
