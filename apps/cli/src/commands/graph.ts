import { DeplyzeError, ErrorCode, type DependencyNode } from '@deplyze/core';
import { createContext, type GlobalFlags } from '../context.js';
import { packageCount } from '@deplyze/scanners';
import { runScanCommand, type ScanFlags } from './shared.js';

export interface GraphFlags extends ScanFlags {
  package?: string;
  depth?: number;
  direction?: 'dependents' | 'dependencies' | 'both';
  limit?: number;
}

const DEFAULT_DEPTH = 4;
const DEFAULT_LIMIT = 500;

function renderTree(
  nodes: DependencyNode[],
  byId: (id: string) => DependencyNode | undefined,
  maxDepth: number,
  limit: number,
): string[] {
  const lines: string[] = [];
  const roots = nodes.filter((node) => node.depth === 0);
  let emitted = 0;

  const label = (node: DependencyNode): string =>
    node.depth === 0
      ? `${node.name} (project)`
      : `${node.name}@${node.version}${node.dev ? ' [dev]' : ''}${node.optional ? ' [optional]' : ''}`;

  const walk = (
    id: string,
    ancestorPrefix: string,
    connector: string,
    depth: number,
    seen: Set<string>,
  ): void => {
    if (depth > maxDepth || emitted >= limit) return;
    const node = byId(id);
    if (!node) return;
    const cycle = seen.has(id);
    lines.push(`${ancestorPrefix}${connector}${cycle ? '↺ ' : ''}${label(node)}`);
    emitted += 1;
    if (cycle) return;

    const nextSeen = new Set(seen);
    nextSeen.add(id);
    const children = node.dependencies
      .map((childId) => byId(childId))
      .filter((child): child is DependencyNode => !!child)
      .sort((a, b) => a.name.localeCompare(b.name));
    const childPrefix = `${ancestorPrefix}${depth === 0 && connector === '' ? '' : connector === '└── ' ? '    ' : '│   '}`;
    children.forEach((child, index) => {
      const last = index === children.length - 1;
      walk(child.id, childPrefix, last ? '└── ' : '├── ', depth + 1, nextSeen);
    });
  };

  for (const root of roots) walk(root.id, '', '', 0, new Set());
  return lines;
}

export async function graphCommand(flags: GraphFlags): Promise<number> {
  const { context, result } = await runScanCommand(flags);
  const graph = result.graph;
  const maxDepth = Math.max(1, Math.min(flags.depth ?? DEFAULT_DEPTH, 50));
  const limit = Math.max(1, Math.min(flags.limit ?? DEFAULT_LIMIT, 5000));
  const format = flags.format ?? (flags.json ? 'json' : 'tree');

  if (format === 'json') {
    process.stdout.write(`${JSON.stringify(graph.toJSON(), null, 2)}\n`);
    return 0;
  }

  if (format === 'mermaid' || format === 'dot') {
    const lines: string[] = [];
    if (format === 'mermaid') lines.push('graph TD');
    else lines.push('digraph dependencies {', '  rankdir=LR;');
    const describe = (node: DependencyNode): string => `${node.name}@${node.version}`;
    for (const node of graph.nodes()) {
      const id = node.id.replace(/[^A-Za-z0-9]/g, '_');
      if (format === 'mermaid') lines.push(`  ${id}["${describe(node)}"]`);
      else lines.push(`  ${id} [label="${describe(node)}"];`);
      for (const dependency of node.dependencies) {
        const target = dependency.replace(/[^A-Za-z0-9]/g, '_');
        lines.push(format === 'mermaid' ? `  ${id} --> ${target}` : `  ${id} -> ${target};`);
      }
    }
    if (format === 'dot') lines.push('}');
    process.stdout.write(`${lines.join('\n')}\n`);
    return 0;
  }

  if (format !== 'tree' && format !== 'terminal') {
    throw new DeplyzeError(ErrorCode.DEPLYZE_E_USAGE, `Unsupported graph format: ${format}`, {
      hint: 'Supported formats: tree, json, mermaid, dot.',
    });
  }

  const byId = (id: string): DependencyNode | undefined => graph.getNode(id);

  if (flags.package) {
    const matches = graph.nodes().filter((node) => node.name === flags.package);
    if (matches.length === 0) {
      process.stdout.write(`${flags.package} is not present in the resolved dependency graph.\n`);
      return 0;
    }
    for (const node of matches) {
      process.stdout.write(
        `\n${node.name}@${node.version}\n${'─'.repeat(Math.min(60, node.name.length + 10))}\n`,
      );
      process.stdout.write(
        `  direct: ${node.direct}  dev: ${node.dev}  optional: ${node.optional}  depth: ${node.depth}\n`,
      );
      const paths = graph.pathsTo(node.id, 5);
      if (paths.length > 0) {
        process.stdout.write('\n  Introduced by:\n');
        for (const path of paths) {
          process.stdout.write(`    ${path.map((id) => describeNode(byId(id), id)).join(' > ')}\n`);
        }
      }
      if (flags.direction === 'dependents' || flags.direction === 'both' || !flags.direction) {
        const dependents = graph.transitiveDependents(node.id).slice(0, flags.limit ?? 25);
        process.stdout.write(`\n  Dependents (${graph.transitiveDependents(node.id).length}):\n`);
        for (const dependent of dependents) {
          process.stdout.write(`    ${dependent.name}@${dependent.version}\n`);
        }
      }
      if (flags.direction === 'dependencies' || flags.direction === 'both') {
        const dependencies = graph.transitiveDependencies(node.id).slice(0, flags.limit ?? 25);
        process.stdout.write(`\n  Dependencies (${graph.transitiveDependencies(node.id).length}):\n`);
        for (const dependency of dependencies) {
          process.stdout.write(`    ${dependency.name}@${dependency.version}\n`);
        }
      }
    }
    void context;
    return 0;
  }

  const lines = renderTree(graph.nodes(), byId, maxDepth, limit);
  process.stdout.write(`${lines.join('\n')}\n`);
  const stats = result.stats;
  process.stdout.write(
    `\n${packageCount(result)} packages · ${stats.edgeCount} edges · max depth ${stats.maxDepth} · ` +
      `${stats.duplicateVersions} duplicate-version package(s)\n`,
  );
  return 0;
}

function describeNode(node: DependencyNode | undefined, id: string): string {
  if (!node) return id;
  return node.depth === 0 ? '(project)' : `${node.name}@${node.version}`;
}

export { createContext };
export type { GlobalFlags };
