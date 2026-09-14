import { readdir } from 'node:fs/promises';
import path from 'node:path';
import { DeplyzeError, ErrorCode, fileExists, readFileSafe } from '@deplyze/core';
import { parse as parseYaml } from 'yaml';
import { matchesGlob } from './glob.js';
import { packageJsonSchema, workspacePatterns, type PackageJson } from './manifest.js';

export type PackageManager = 'npm' | 'pnpm' | 'yarn' | 'bun' | 'unknown';

export interface DetectedLockfile {
  path: string;
  manager: Exclude<PackageManager, 'unknown'>;
}

export interface DetectedProject {
  root: string;
  manager: PackageManager;
  lockfiles: DetectedLockfile[];
  /** Absolute paths of workspace manifests, including the root manifest. */
  manifests: string[];
  rootManifestPath: string;
  rootManifest: PackageJson;
}

const LOCKFILE_MANAGERS: Array<{ file: string; manager: Exclude<PackageManager, 'unknown'> }> = [
  { file: 'pnpm-lock.yaml', manager: 'pnpm' },
  { file: 'yarn.lock', manager: 'yarn' },
  { file: 'bun.lock', manager: 'bun' },
  { file: 'bun.lockb', manager: 'bun' },
  { file: 'package-lock.json', manager: 'npm' },
];

const SKIP_DIRS = new Set([
  'node_modules',
  '.git',
  '.hg',
  '.svn',
  'dist',
  'build',
  'out',
  'coverage',
  '.next',
  '.nuxt',
  '.turbo',
  '.cache',
  'vendor',
  '__pycache__',
]);

export interface DetectOptions {
  /** Maximum directory depth when searching for workspace manifests. */
  maxDepth?: number;
  /** Extra directories to skip during discovery. */
  exclude?: string[];
}

/**
 * Discover the project root contents: manifests, lockfiles and the package
 * manager that produced them.
 */
export async function detectProject(root: string, options: DetectOptions = {}): Promise<DetectedProject> {
  const manifestPath = path.join(root, 'package.json');
  if (!(await fileExists(manifestPath))) {
    throw new DeplyzeError(ErrorCode.DEPLYZE_E_NO_MANIFEST, `No package.json found in ${root}.`, {
      hint: 'Run Deplyze from a JavaScript/TypeScript project root, or pass --path <dir>.',
    });
  }
  const rootManifest = packageJsonSchema.parse(JSON.parse(await readFileSafe(manifestPath)));

  const lockfiles: DetectedLockfile[] = [];
  for (const { file, manager } of LOCKFILE_MANAGERS) {
    if (await fileExists(path.join(root, file))) {
      lockfiles.push({ path: file, manager });
    }
  }

  const manager = inferManager(rootManifest, lockfiles);
  const extraPatterns = await readWorkspacePatterns(root);
  const manifests = await discoverWorkspaceManifests(root, rootManifest, options, extraPatterns);

  return { root, manager, lockfiles, manifests, rootManifestPath: 'package.json', rootManifest };
}

function inferManager(manifest: PackageJson, lockfiles: DetectedLockfile[]): PackageManager {
  const declared = manifest.packageManager?.split('@')[0];
  if (declared === 'npm' || declared === 'pnpm' || declared === 'yarn' || declared === 'bun') {
    // A declared manager only wins when the matching lockfile is present;
    // otherwise we trust the lockfile that actually exists.
    if (lockfiles.some((lock) => lock.manager === declared)) return declared;
  }
  const pnpm = lockfiles.find((lock) => lock.manager === 'pnpm');
  if (pnpm) return 'pnpm';
  const yarn = lockfiles.find((lock) => lock.manager === 'yarn');
  if (yarn) return 'yarn';
  const bun = lockfiles.find((lock) => lock.manager === 'bun');
  if (bun) return 'bun';
  const npm = lockfiles.find((lock) => lock.manager === 'npm');
  if (npm) return 'npm';
  return lockfiles[0]?.manager ?? 'unknown';
}

/**
 * Read workspace globs from `pnpm-workspace.yaml` and `lerna.json`, in
 * addition to the `workspaces` field of the root manifest.
 */
async function readWorkspacePatterns(root: string): Promise<string[]> {
  const patterns: string[] = [];
  const pnpmWorkspace = path.join(root, 'pnpm-workspace.yaml');
  if (await fileExists(pnpmWorkspace)) {
    try {
      const data = parseYaml(await readFileSafe(pnpmWorkspace)) as { packages?: unknown };
      if (Array.isArray(data?.packages)) {
        patterns.push(...data.packages.filter((entry): entry is string => typeof entry === 'string'));
      }
    } catch {
      // A malformed pnpm-workspace.yaml is reported by the manifest parser later.
    }
  }
  const lerna = path.join(root, 'lerna.json');
  if (await fileExists(lerna)) {
    try {
      const data = JSON.parse(await readFileSafe(lerna)) as { packages?: unknown };
      if (Array.isArray(data?.packages)) {
        patterns.push(...data.packages.filter((entry): entry is string => typeof entry === 'string'));
      }
    } catch {
      /* ignore */
    }
  }
  return patterns;
}

async function discoverWorkspaceManifests(
  root: string,
  rootManifest: PackageJson,
  options: DetectOptions,
  extraPatterns: string[] = [],
): Promise<string[]> {
  const patterns = [...workspacePatterns(rootManifest), ...extraPatterns];
  const maxDepth = options.maxDepth ?? 5;
  const exclude = new Set([...SKIP_DIRS, ...(options.exclude ?? [])]);
  const results = new Set<string>([path.join(root, 'package.json')]);

  const candidateDirs: string[] = [];
  const walk = async (dir: string, depth: number): Promise<void> => {
    if (depth > maxDepth) return;
    let entries;
    try {
      entries = await readdir(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const entry of entries) {
      if (!entry.isDirectory()) continue;
      if (exclude.has(entry.name)) continue;
      const child = path.join(dir, entry.name);
      const relative = path.relative(root, child).split(path.sep).join('/');
      if (patterns.length > 0 && patterns.some((pattern) => matchesGlob(relative, pattern))) {
        if (await hasManifest(child)) candidateDirs.push(child);
      }
      await walk(child, depth + 1);
    }
  };

  if (patterns.length > 0) {
    await walk(root, 0);
  } else {
    // No workspace declaration: still pick up npm/pnpm/yarn workspace folders
    // declared via lockfile `importers` is handled by the loader; here we look
    // for an obvious `packages/*` or `apps/*` layout so monorepos without a
    // `workspaces` field are not silently treated as single projects.
    for (const dir of ['packages', 'apps', 'libs', 'services', 'workspaces']) {
      const base = path.join(root, dir);
      let entries;
      try {
        entries = await readdir(base, { withFileTypes: true });
      } catch {
        continue;
      }
      for (const entry of entries) {
        if (!entry.isDirectory()) continue;
        if (exclude.has(entry.name)) continue;
        const child = path.join(base, entry.name);
        if (await hasManifest(child)) results.add(path.join(child, 'package.json'));
      }
    }
  }

  for (const dir of candidateDirs) {
    results.add(path.join(dir, 'package.json'));
  }
  return [...results];
}

async function hasManifest(dir: string): Promise<boolean> {
  return fileExists(path.join(dir, 'package.json'));
}
