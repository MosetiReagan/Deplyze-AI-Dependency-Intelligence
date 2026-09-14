import type { DependencyGraph, DependencyNode } from '@deplyze/core';

/** Render a node id as `name@version` (roots render as their workspace name). */
export function nodeLabel(node: DependencyNode | undefined, id: string): string {
  if (!node) return id;
  if (node.depth === 0) return `${node.name} (project)`;
  return `${node.name}@${node.version}`;
}

export function formatPath(graph: DependencyGraph, ids: string[]): string {
  return ids.map((id) => nodeLabel(graph.getNode(id), id)).join(' > ');
}

export interface DependencyPathInfo {
  ids: string[];
  formatted: string;
  /** Direct dependency that introduces this package, when there is one. */
  introducedBy?: string;
}

export function dependencyPaths(graph: DependencyGraph, nodeId: string, limit = 3): DependencyPathInfo[] {
  const paths = graph.pathsTo(nodeId, limit);
  return paths.map((ids) => {
    const info: DependencyPathInfo = { ids, formatted: formatPath(graph, ids) };
    const introducer = ids.find((id) => {
      const node = graph.getNode(id);
      return node?.direct === true;
    });
    if (introducer) {
      const node = graph.getNode(introducer);
      if (node) info.introducedBy = `${node.name}@${node.version}`;
    }
    return info;
  });
}

export function countDependents(graph: DependencyGraph, nodeId: string): number {
  return graph.transitiveDependents(nodeId).length;
}
