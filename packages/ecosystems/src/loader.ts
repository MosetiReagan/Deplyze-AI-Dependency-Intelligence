import path from 'node:path';
import {
  DependencyGraph,
  DeplyzeError,
  ErrorCode,
  Logger,
  compareVersions,
  parseVersion,
  readFileSafe,
  satisfies,
  type DependencyKind,
  type LockfileInfo,
  type ModelWarning,
  type ProjectModel,
  type Workspace,
} from '@deplyze/core';
import { detectProject } from './detect.js';
import { declarationsOf, licenseOf, packageJsonSchema, type PackageJson } from './manifest.js';
import type { LockfileParser, ParsedLockfile, ResolvedPackage } from './model.js';
import { npmLockParser } from './npm-lock.js';
import { pnpmLockParser } from './pnpm-lock.js';
import { yarnLockParser } from './yarn-lock.js';
import { bunBinaryLockParser, bunLockParser } from './bun-lock.js';

export interface LoadOptions {
  maxFileBytes?: number;
  /** Emit debug logging during loading. */
  logger?: Logger;
  /** Extra directories to exclude from workspace discovery. */
  exclude?: string[];
  /** Override detection (used by tests and `--manager`). */
  forceManager?: 'npm' | 'pnpm' | 'yarn' | 'bun';
}

export interface LoadedProject {
  project: ProjectModel;
  graph: DependencyGraph;
}

const PARSERS: LockfileParser[] = [
  pnpmLockParser,
  yarnLockParser,
  bunLockParser,
  bunBinaryLockParser,
  npmLockParser,
];

function parserFor(file: string): LockfileParser | undefined {
  const base = path.basename(file);
  return PARSERS.find((parser) => parser.detect(base));
}

/** Parse `npm:alias@1.2.3` style protocol specifiers. */
function parseAlias(spec: string): { name: string; spec: string } | undefined {
  if (!spec.startsWith('npm:')) return undefined;
  const rest = spec.slice(4);
  const at = rest.lastIndexOf('@');
  if (at <= 0) return { name: rest, spec: '*' };
  return { name: rest.slice(0, at), spec: rest.slice(at + 1) };
}

function isNonRegistrySpec(spec: string): boolean {
  return (
    spec.startsWith('workspace:') ||
    spec.startsWith('link:') ||
    spec.startsWith('file:') ||
    spec.startsWith('portal:') ||
    spec.startsWith('patch:') ||
    spec.startsWith('git+') ||
    spec.startsWith('github:') ||
    spec.startsWith('http://') ||
    spec.startsWith('https://') ||
    spec.includes('://')
  );
}

/**
 * Build a dependency graph index keyed by package name.
 *
 * A real npm tree can contain several copies of the same package. Deplyze
 * resolves a dependency specifier to the highest satisfying version present in
 * the lockfile, which matches hoisted-install semantics for the overwhelming
 * majority of trees. When no version satisfies the spec it falls back to the
 * highest available version and records a warning, rather than inventing a
 * version that is not in the lockfile.
 */
class PackageIndex {
  private readonly byName = new Map<string, ResolvedPackage[]>();
  readonly ambiguous = new Map<string, number>();

  add(pkg: ResolvedPackage): void {
    const list = this.byName.get(pkg.name) ?? [];
    if (list.some((existing) => existing.version === pkg.version)) {
      this.ambiguous.set(pkg.name, (this.ambiguous.get(pkg.name) ?? 0) + 1);
      return;
    }
    list.push(pkg);
    this.byName.set(pkg.name, list);
  }

  finalize(): void {
    for (const list of this.byName.values()) {
      list.sort((a, b) => compareVersions(b.version, a.version));
    }
  }

  versionsOf(name: string): string[] {
    return (this.byName.get(name) ?? []).map((pkg) => pkg.version);
  }

  get(name: string): ResolvedPackage | undefined {
    return this.byName.get(name)?.[0];
  }

  has(name: string): boolean {
    return this.byName.has(name);
  }

  resolve(name: string, spec: string, exactVersion?: string): ResolvedPackage | undefined {
    const candidates = this.byName.get(name);
    if (!candidates || candidates.length === 0) return undefined;
    if (exactVersion) {
      const exact = candidates.find((pkg) => pkg.version === exactVersion);
      if (exact) return exact;
    }
    const normalized = spec && spec !== '*' ? spec : undefined;
    if (normalized) {
      const exact = candidates.find((pkg) => pkg.version === normalized);
      if (exact) return exact;
      const matching = candidates.find((pkg) => satisfies(pkg.version, normalized));
      if (matching) return matching;
    }
    return candidates[0];
  }

  all(): ResolvedPackage[] {
    return [...this.byName.values()].flat();
  }
}

export async function loadProject(root: string, options: LoadOptions = {}): Promise<LoadedProject> {
  const logger = options.logger ?? new Logger({ level: 'silent' });
  const warnings: ModelWarning[] = [];
  const detected = await detectProject(root, { exclude: options.exclude });

  // 1. Read every workspace manifest.
  const workspaces: Workspace[] = [];
  for (const manifestPath of detected.manifests) {
    const relative = path.relative(detected.root, manifestPath).split(path.sep).join('/');
    const workspacePath = path.dirname(relative) === '.' ? '.' : path.dirname(relative);
    let manifest: PackageJson;
    try {
      manifest = packageJsonSchema.parse(JSON.parse(await readFileSafe(manifestPath, options.maxFileBytes)));
    } catch (error) {
      if (error instanceof DeplyzeError) throw error;
      warnings.push({
        code: 'manifest.unreadable',
        message: `Skipped unreadable manifest at ${relative}.`,
        path: relative,
      });
      continue;
    }
    const workspace: Workspace = {
      path: workspacePath,
      name: typeof manifest.name === 'string' ? manifest.name : workspacePath,
      private: manifest.private ?? false,
      declared: declarationsOf(manifest, relative),
    };
    if (typeof manifest.version === 'string') workspace.version = manifest.version;
    workspaces.push(workspace);
  }
  workspaces.sort((a, b) => (a.path === '.' ? -1 : b.path === '.' ? 1 : a.path.localeCompare(b.path)));

  // 2. Parse the lockfile (if any).
  const lockfileInfos: LockfileInfo[] = [];
  const lockResults: Array<{ info: LockfileInfo; parsed: ParsedLockfile }> = [];
  const lockfilesToTry = options.forceManager
    ? detected.lockfiles.filter((lock) => lock.manager === options.forceManager)
    : detected.lockfiles;

  for (const lockfile of lockfilesToTry) {
    const absolute = path.join(detected.root, lockfile.path);
    const parser = parserFor(lockfile.path);
    if (!parser) {
      lockfileInfos.push({
        path: lockfile.path,
        manager: lockfile.manager,
        parsed: false,
        note: 'No parser registered for this lockfile.',
        resolvedPackages: 0,
      });
      continue;
    }
    try {
      const raw = await readFileSafe(absolute, options.maxFileBytes);
      const parsed = parser.parse(raw, lockfile.path);
      const info: LockfileInfo = {
        path: lockfile.path,
        manager: lockfile.manager,
        parsed: true,
        resolvedPackages: parsed.packages.length,
      };
      if (parsed.formatVersion) info.formatVersion = parsed.formatVersion;
      if (parsed.notes.length > 0) info.note = parsed.notes.join(' ');
      lockfileInfos.push(info);
      lockResults.push({ info, parsed });
    } catch (error) {
      if (error instanceof DeplyzeError && error.code === ErrorCode.DEPLYZE_E_LOCKFILE_UNSUPPORTED) {
        lockfileInfos.push({
          path: lockfile.path,
          manager: lockfile.manager,
          parsed: false,
          note: error.message,
          resolvedPackages: 0,
        });
        warnings.push({
          code: 'lockfile.unsupported',
          message: error.message,
          path: lockfile.path,
          hint: error.hint,
        });
        continue;
      }
      throw error;
    }
  }

  // Prefer the richest lockfile when several are present.
  lockResults.sort((a, b) => b.parsed.packages.length - a.parsed.packages.length);
  const primary = lockResults[0]?.parsed;

  // 3. Build the package index, falling back to manifest ranges when needed.
  const index = new PackageIndex();
  if (primary) {
    for (const pkg of primary.packages) index.add(pkg);
  }
  if (index.all().length === 0) {
    warnings.push({
      code: 'lockfile.absent',
      message:
        'No lockfile was found (or it contained no resolvable packages). Deplyze analyzed manifest ranges, so transitive dependencies and exact versions are unknown.',
      hint: 'Commit a lockfile (package-lock.json, pnpm-lock.yaml, yarn.lock or bun.lock) for a complete analysis.',
    });
    for (const workspace of workspaces) {
      for (const declaration of workspace.declared) {
        index.add({
          name: declaration.name,
          version: declaration.range,
          ecosystem: 'npm',
          locator: `${workspace.path}:${declaration.name}`,
        });
      }
    }
  }
  index.finalize();

  for (const [name, count] of index.ambiguous) {
    if (count > 0) {
      warnings.push({
        code: 'lockfile.duplicate-locations',
        message: `Package "${name}" appears in more than one lockfile location; Deplyze resolves it to the highest matching version.`,
      });
    }
  }

  // 4. Workspace link map so monorepo packages resolve to each other.
  const graph = new DependencyGraph();
  const workspaceRoots = new Map<string, string>();
  for (const workspace of workspaces) {
    const version = workspace.version ?? '0.0.0';
    const id = `root:${workspace.path}`;
    workspaceRoots.set(workspace.name, id);
    graph.addNode({
      id,
      name: workspace.name,
      version,
      ecosystem: 'npm',
      direct: false,
      dev: false,
      optional: false,
      peer: false,
      depth: 0,
      dependencies: [],
      workspace: workspace.path,
    });
  }

  // 5. Seed direct edges from workspace declarations (honouring lockfile pins).
  const pins = new Map<string, string>();
  for (const ref of primary?.imports ?? []) {
    if (!ref.resolvedVersion) continue;
    pins.set(`${ref.importer}|${ref.name}|${ref.kind}`, ref.resolvedVersion);
  }

  const edgeKindFor = (kind: DependencyKind): 'prod' | 'dev' | 'optional' | 'peer' => kind;

  const expanded = new Set<string>();
  const bestDepth = new Map<string, number>();
  for (const workspace of workspaces) {
    bestDepth.set(`root:${workspace.path}`, 0);
  }
  const enqueueDependencies = (nodeId: string, resolved: ResolvedPackage, depth: number): void => {
    for (const [depName, depSpec] of Object.entries(resolved.dependencies ?? {})) {
      enqueueDep(nodeId, depName, depSpec, 'prod', depth + 1, false);
    }
    for (const [depName, depSpec] of Object.entries(resolved.optionalDependencies ?? {})) {
      enqueueDep(nodeId, depName, depSpec, 'optional', depth + 1, true);
    }
    for (const [depName, depSpec] of Object.entries(resolved.peerDependencies ?? {})) {
      enqueueDep(nodeId, depName, depSpec, 'peer', depth + 1, false);
    }
  };

  const enqueueDep = (
    fromId: string,
    depName: string,
    depSpec: string,
    kind: 'prod' | 'dev' | 'optional' | 'peer',
    depth: number,
    optionalEdge: boolean,
  ): void => {
    if (isNonRegistrySpec(depSpec) && !depSpec.startsWith('npm:')) {
      const linked = workspaceRoots.get(depName);
      if (linked) {
        graph.addEdge(fromId, linked, kind);
        const parent = graph.getNode(fromId);
        if (parent && !parent.dependencies.includes(linked)) parent.dependencies.push(linked);
      }
      return;
    }
    const alias = parseAlias(depSpec);
    const targetName = alias?.name ?? depName;
    const targetSpec = alias?.spec ?? depSpec;

    const linkedWorkspace = workspaceRoots.get(targetName);
    if (linkedWorkspace) {
      graph.addEdge(fromId, linkedWorkspace, kind);
      const parent = graph.getNode(fromId);
      if (parent && !parent.dependencies.includes(linkedWorkspace)) parent.dependencies.push(linkedWorkspace);
      return;
    }

    const resolved = index.resolve(targetName, targetSpec);
    if (!resolved) {
      return;
    }
    const id = DependencyGraph.nodeId('npm', resolved.name, resolved.version);
    const existing = graph.getNode(id);
    if (!existing) {
      graph.addNode({
        id,
        name: resolved.name,
        version: resolved.version,
        ecosystem: 'npm',
        direct: false,
        dev: false,
        optional: optionalEdge || resolved.optional === true,
        peer: kind === 'peer',
        depth,
        dependencies: [],
        ...(resolved.resolved ? { resolved: resolved.resolved } : {}),
        ...(resolved.integrity ? { integrity: resolved.integrity } : {}),
        ...(resolved.license ? { license: resolved.license } : {}),
        ...(resolved.deprecated !== undefined ? { deprecated: !!resolved.deprecated } : {}),
        ...(resolved.scripts ? { scripts: resolved.scripts } : {}),
        ...(resolved.engines ? { engines: resolved.engines } : {}),
      });
    }
    graph.addEdge(fromId, id, kind);
    const parent = graph.getNode(fromId);
    if (parent && !parent.dependencies.includes(id)) parent.dependencies.push(id);

    const previous = bestDepth.get(id);
    if (previous === undefined || depth < previous) {
      bestDepth.set(id, depth);
      const node = graph.getNode(id);
      if (node) node.depth = depth;
    }
    if (!expanded.has(id)) {
      expanded.add(id);
      enqueueDependencies(id, resolved, depth);
    }
  };

  for (const workspace of workspaces) {
    const rootId = `root:${workspace.path}`;
    for (const declaration of workspace.declared) {
      const pin = pins.get(`${workspace.path}|${declaration.name}|${declaration.kind}`);
      const linked = workspaceRoots.get(declaration.name);
      const resolved = index.resolve(declaration.name, declaration.range, pin);
      if (!resolved && linked) {
        // A workspace package referenced with a normal semver range.
        graph.addEdge(rootId, linked, edgeKindFor(declaration.kind));
        const root = graph.getNode(rootId);
        if (root && !root.dependencies.includes(linked)) root.dependencies.push(linked);
        continue;
      }
      if (!resolved) {
        warnings.push({
          code: 'dependency.unresolved',
          message: `Could not resolve "${declaration.name}@${declaration.range}" declared in ${
            workspace.path === '.' ? 'package.json' : `${workspace.path}/package.json`
          }.`,
          hint: 'Run your package manager install to refresh the lockfile.',
        });
        continue;
      }
      enqueueDep(
        rootId,
        declaration.name,
        pin ?? declaration.range,
        edgeKindFor(declaration.kind),
        1,
        declaration.kind === 'optional',
      );
      const nodeId = DependencyGraph.nodeId('npm', resolved.name, resolved.version);
      const node = graph.getNode(nodeId);
      if (node) {
        node.direct = true;
        if (!node.declaredRange) node.declaredRange = declaration.range;
        node.workspace = workspace.path;
        if (declaration.kind === 'dev') node.dev = true;
        if (declaration.kind === 'optional') node.optional = true;
        if (declaration.kind === 'peer') node.peer = true;
      }
    }
  }

  // 6. Classify dev/optional by reachability, so a package that is *also*
  //    reachable from production code is never mislabeled as dev-only.
  classifyReachability(graph, [...workspaceRoots.values()]);

  // 7. Attach the project's own license to... nothing; licenses come per-package.

  const manager = options.forceManager ?? detected.manager;
  const project: ProjectModel = {
    root: detected.root,
    name:
      typeof detected.rootManifest.name === 'string'
        ? detected.rootManifest.name
        : path.basename(detected.root),
    private: detected.rootManifest.private ?? false,
    manager,
    lockfiles: lockfileInfos,
    workspaces,
    nodes: graph.nodes(),
    warnings,
  };
  if (typeof detected.rootManifest.version === 'string') project.version = detected.rootManifest.version;

  const rootLicense = licenseOf(detected.rootManifest);
  if (rootLicense) {
    const rootNode = graph.getNode('root:.');
    if (rootNode) rootNode.license = rootLicense;
  }

  logger.debug('Project loaded', {
    manager,
    nodes: graph.size,
    edges: graph.edgeCount,
    workspaces: workspaces.length,
  });

  return { project: { ...project, nodes: graph.nodes() }, graph };
}

/**
 * Mark nodes as dev/optional when *every* path from a workspace root reaches
 * them through a dev or optional edge.
 */
function classifyReachability(graph: DependencyGraph, rootIds: string[]): void {
  const prodReachable = new Set<string>(rootIds);
  const nonOptionalReachable = new Set<string>(rootIds);

  const propagate = (seed: Set<string>, excludedKinds: Set<string>): void => {
    const queue = [...seed];
    const seen = new Set<string>(seed);
    while (queue.length > 0) {
      const current = queue.shift() as string;
      const node = graph.getNode(current);
      if (!node) continue;
      for (const depId of node.dependencies) {
        const kind = graph.edgeKind(current, depId);
        if (kind && excludedKinds.has(kind)) continue;
        if (seen.has(depId)) continue;
        seen.add(depId);
        seed.add(depId);
        queue.push(depId);
      }
    }
  };

  propagate(prodReachable, new Set(['dev']));
  propagate(nonOptionalReachable, new Set(['optional']));

  for (const node of graph.allNodes()) {
    if (node.depth === 0) continue;
    if (!prodReachable.has(node.id)) node.dev = true;
    if (!nonOptionalReachable.has(node.id)) node.optional = true;
  }
}

export function summarizeProject(project: ProjectModel) {
  const stats = {
    dependencies: project.nodes.filter((node) => node.depth > 0).length,
    direct: project.nodes.filter((node) => node.direct).length,
  };
  return stats;
}

export { parseVersion };
