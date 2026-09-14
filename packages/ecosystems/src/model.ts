import type { DependencyKind, Ecosystem } from '@deplyze/core';

/** A package resolved by a lockfile (or a manifest fallback). */
export interface ResolvedPackage {
  name: string;
  version: string;
  ecosystem: Ecosystem;
  resolved?: string;
  integrity?: string;
  license?: string;
  deprecated?: boolean | string;
  scripts?: Record<string, string>;
  engines?: Record<string, string>;
  /** Dependency name -> specifier recorded by the lockfile. */
  dependencies?: Record<string, string>;
  optionalDependencies?: Record<string, string>;
  peerDependencies?: Record<string, string>;
  /** True when the package is only reachable through dev edges. */
  dev?: boolean;
  optional?: boolean;
  peer?: boolean;
  /** Lockfile location key, useful for debugging resolution. */
  locator?: string;
}

/** A direct dependency declared by a workspace importer. */
export interface ImportedRef {
  /** Workspace path relative to the project root; `.` for the root project. */
  importer: string;
  name: string;
  range: string;
  kind: DependencyKind;
  /** Exact version when the lockfile pinned it (pnpm records this). */
  resolvedVersion?: string;
}

export interface ParsedLockfile {
  manager: 'npm' | 'pnpm' | 'yarn' | 'bun';
  formatVersion?: string;
  packages: ResolvedPackage[];
  imports: ImportedRef[];
  /** Non-fatal observations surfaced to the user. */
  notes: string[];
}

export interface LockfileParser {
  manager: ParsedLockfile['manager'];
  filename: string;
  /** Cheap sniff test to confirm the file matches this parser. */
  detect: (filename: string) => boolean;
  parse: (raw: string, filename: string) => ParsedLockfile;
}
