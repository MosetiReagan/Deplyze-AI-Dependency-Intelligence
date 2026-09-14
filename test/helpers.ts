/**
 * Shared test builders.
 *
 * `ScanResult` is a wide, interlinked structure (graph + statistics + risk +
 * diagnostics). Building it by hand in every suite invites drift, so tests
 * construct results through this helper instead. The helper never touches the
 * network and produces byte-for-byte deterministic output.
 */
import {
  DependencyGraph,
  Logger,
  createFinding,
  summarize,
  type DependencyNode,
  type Finding,
  type ProjectModel,
} from '@deplyze/core';
import { defaultConfig, type ResolvedConfig } from '@deplyze/config';
import { scoreRisk } from '@deplyze/risk';
import { OsvClient } from '@deplyze/advisories';
import {
  RegistryClient,
  type RegistryMetadata,
  type ScanContext,
  type ScanResult,
  type SourceUsage,
} from '@deplyze/scanners';

export function makeNode(
  overrides: Partial<DependencyNode> & Pick<DependencyNode, 'name' | 'version'>,
): DependencyNode {
  const base: DependencyNode = {
    id: `npm:${overrides.name}@${overrides.version}`,
    name: overrides.name,
    version: overrides.version,
    ecosystem: 'npm',
    direct: false,
    dev: false,
    optional: false,
    peer: false,
    depth: 1,
    dependencies: [],
  };
  return { ...base, ...overrides };
}

export const ROOT_NODE: DependencyNode = {
  id: 'root:.',
  name: 'fixture-app',
  version: '1.0.0',
  ecosystem: 'npm',
  direct: false,
  dev: false,
  optional: false,
  peer: false,
  depth: 0,
  dependencies: [],
};

export function makeFinding(overrides: Partial<Finding> = {}): Finding {
  const base = createFinding({
    category: overrides.category ?? 'vulnerability',
    severity: overrides.severity ?? 'high',
    confidence: overrides.confidence ?? 'high',
    title: overrides.title ?? 'Example finding',
    description: overrides.description ?? 'An example finding used by tests.',
    source: overrides.source ?? 'security/vulnerability',
    package: overrides.package ?? 'lodash',
    version: overrides.version ?? '4.17.20',
    stableId: overrides.id,
  });
  return { ...base, ...overrides, id: overrides.id ?? base.id };
}

export interface MakeResultOptions {
  nodes?: DependencyNode[];
  edges?: Array<[string, string]>;
  findings?: Finding[];
  config?: ResolvedConfig;
  root?: string;
  name?: string;
  workspaces?: number;
}

export function makeResult(options: MakeResultOptions = {}): ScanResult {
  const graph = new DependencyGraph();
  const nodes = options.nodes ?? [
    ROOT_NODE,
    makeNode({ name: 'lodash', version: '4.17.20', direct: true, declaredRange: '^4.17.0' }),
    makeNode({ name: 'minimist', version: '1.2.0', depth: 2, license: 'MIT' }),
  ];
  for (const node of nodes) graph.addNode(node);
  const edges = options.edges ?? [
    ['root:.', 'npm:lodash@4.17.20'],
    ['npm:lodash@4.17.20', 'npm:minimist@1.2.0'],
  ];
  for (const [from, to] of edges) graph.addEdge(from, to);

  const findings = options.findings ?? [];
  const stats = graph.stats();
  const root = options.root ?? process.cwd();
  const name = options.name ?? 'fixture-app';
  const workspacePaths = Array.from({ length: options.workspaces ?? 1 }, (_, index) =>
    index === 0 ? '.' : `packages/w${index}`,
  );

  const project: ProjectModel = {
    root,
    name,
    version: '1.0.0',
    private: true,
    manager: 'npm',
    lockfiles: [
      {
        path: 'package-lock.json',
        manager: 'npm',
        formatVersion: '3',
        parsed: true,
        resolvedPackages: nodes.length - 1,
      },
    ],
    workspaces: workspacePaths.map((path) => ({
      path,
      name: path === '.' ? name : `w${path}`,
      version: '1.0.0',
      private: true,
      declared: [],
    })),
    nodes,
    warnings: [],
  };

  return {
    version: 1,
    project,
    graph,
    findings,
    risk: scoreRisk({ findings, stats, directDependencies: stats.directNodes }),
    summary: summarize(findings),
    stats,
    diagnostics: {
      scannerErrors: [],
      unresolvedAdvisories: [],
      usedNetwork: false,
      usedCache: false,
      registryPackagesResolved: 0,
      registryPackagesMissing: 0,
      registryFromCache: 0,
      sourceFilesScanned: 0,
      durationMs: 5,
      unparsedLockfiles: [],
    },
    config: options.config ?? defaultConfig(),
    startedAt: '2025-01-01T00:00:00.000Z',
    finishedAt: '2025-01-01T00:00:00.005Z',
  };
}

/**
 * Build a `ScanContext` for scanner unit tests. Network clients are constructed
 * in offline/disabled mode so a test can never accidentally call out.
 */
export function makeContext(
  options: MakeResultOptions & { metadata?: Map<string, RegistryMetadata>; sourceUsage?: SourceUsage } = {},
): ScanContext {
  const result = makeResult(options);
  const context: ScanContext = {
    root: result.project.root,
    project: result.project,
    graph: result.graph,
    config: result.config,
    registry: new RegistryClient({ enabled: false, offline: true }),
    advisories: new OsvClient({ offline: true }),
    logger: new Logger({ level: 'silent' }),
    registryMetadata: options.metadata ?? new Map(),
  };
  if (options.sourceUsage) context.sourceUsage = options.sourceUsage;
  return context;
}

export function makeSourceUsage(overrides: Partial<SourceUsage> = {}): SourceUsage {
  return {
    imported: new Map(),
    scriptCommands: new Set(),
    configReferences: new Set(),
    filesScanned: 0,
    bytesScanned: 0,
    truncated: false,
    hasDynamicImports: false,
    skippedFiles: 0,
    ...overrides,
  };
}
