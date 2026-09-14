import { DeplyzeError, ErrorCode } from '@deplyze/core';
import type { DependencyKind } from '@deplyze/core';
import { parseJsonc } from './jsonc.js';
import type { LockfileParser, ParsedLockfile, ResolvedPackage } from './model.js';

type BunTuple = [string, string?, Record<string, unknown>?, string?, ...unknown[]];

interface BunLockfile {
  lockfileVersion?: number;
  workspaces?: Record<
    string,
    {
      name?: string;
      dependencies?: Record<string, string>;
      devDependencies?: Record<string, string>;
      optionalDependencies?: Record<string, string>;
      peerDependencies?: Record<string, string>;
    }
  >;
  packages?: Record<string, BunTuple | Record<string, unknown>>;
}

function splitResolution(resolution: string): { name: string; version: string } | undefined {
  const at = resolution.lastIndexOf('@');
  if (at <= 0) return undefined;
  return { name: resolution.slice(0, at), version: resolution.slice(at + 1) };
}

function pickDeps(value: unknown): Record<string, string> | undefined {
  if (!value || typeof value !== 'object') return undefined;
  const result: Record<string, string> = {};
  for (const [name, spec] of Object.entries(value as Record<string, unknown>)) {
    if (typeof spec === 'string') result[name] = spec;
    else if (spec && typeof spec === 'object') {
      const version = (spec as { version?: unknown }).version;
      if (typeof version === 'string') result[name] = version;
    }
  }
  return Object.keys(result).length > 0 ? result : undefined;
}

export const bunLockParser: LockfileParser = {
  manager: 'bun',
  filename: 'bun.lock',
  detect: (filename) => filename === 'bun.lock',
  parse(raw, filename): ParsedLockfile {
    let data: BunLockfile;
    try {
      data = parseJsonc(raw) as BunLockfile;
    } catch (error) {
      throw new DeplyzeError(
        ErrorCode.DEPLYZE_E_LOCKFILE_PARSE,
        `Could not parse ${filename}: invalid JSON.`,
        {
          hint: 'Regenerate the lockfile with `bun install`.',
          cause: error,
        },
      );
    }
    const packages: ResolvedPackage[] = [];
    const imports: ParsedLockfile['imports'] = [];
    const notes: string[] = [];

    for (const [importer, workspace] of Object.entries(data.workspaces ?? {})) {
      const path = importer === '' ? '.' : importer;
      const sections: Array<[DependencyKind, Record<string, string> | undefined]> = [
        ['prod', workspace?.dependencies],
        ['dev', workspace?.devDependencies],
        ['optional', workspace?.optionalDependencies],
        ['peer', workspace?.peerDependencies],
      ];
      for (const [kind, deps] of sections) {
        if (!deps) continue;
        for (const [name, range] of Object.entries(deps)) {
          if (typeof range !== 'string') continue;
          imports.push({ importer: path, name, range, kind });
        }
      }
    }

    for (const [key, value] of Object.entries(data.packages ?? {})) {
      let resolution = key;
      let deps: Record<string, string> | undefined;
      let integrity: string | undefined;
      if (Array.isArray(value)) {
        const tuple = value as BunTuple;
        if (typeof tuple[0] === 'string') resolution = tuple[0];
        deps = pickDeps(tuple[2]);
        if (typeof tuple[3] === 'string') integrity = tuple[3];
      } else if (value && typeof value === 'object') {
        const record = value as Record<string, unknown>;
        if (typeof record.resolution === 'string') resolution = record.resolution;
        if (typeof record.integrity === 'string') integrity = record.integrity;
        deps = pickDeps(record.dependencies);
      }
      const parsed = splitResolution(resolution);
      if (!parsed) {
        notes.push(`Skipped unrecognized bun package entry: ${key}`);
        continue;
      }
      const pkg: ResolvedPackage = {
        name: parsed.name,
        version: parsed.version,
        ecosystem: 'npm',
        locator: key,
        dependencies: deps,
      };
      if (integrity) pkg.integrity = integrity;
      packages.push(pkg);
    }

    return {
      manager: 'bun',
      formatVersion: data.lockfileVersion !== undefined ? String(data.lockfileVersion) : undefined,
      packages,
      imports,
      notes,
    };
  },
};

/** `bun.lockb` is a binary format; Deplyze refuses to guess at its contents. */
export const bunBinaryLockParser: LockfileParser = {
  manager: 'bun',
  filename: 'bun.lockb',
  detect: (filename) => filename === 'bun.lockb',
  parse(): ParsedLockfile {
    return {
      manager: 'bun',
      packages: [],
      imports: [],
      notes: [
        'bun.lockb is a binary lockfile and is not parsed by Deplyze. Run `bun install --save-text-lockfile` to generate bun.lock, or Deplyze will fall back to manifest ranges.',
      ],
    };
  },
};
