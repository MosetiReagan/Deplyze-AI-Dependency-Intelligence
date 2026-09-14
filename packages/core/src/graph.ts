import type { DependencyNode, GraphStats } from './types.js';

export interface GraphEdge {
  from: string;
  to: string;
  kind: 'prod' | 'dev' | 'optional' | 'peer';
}

export interface TraversalOptions {
  /** Hard cap on visited nodes to bound work on pathological graphs. */
  maxNodes?: number;
  /** Maximum depth to traverse. */
  maxDepth?: number;
}

const DEFAULT_MAX_NODES = 250_000;

/**
 * A directed dependency graph.
 *
 * Nodes are identified by `<ecosystem>:<name>@<version>`. Edges point from a
 * dependent to its dependency. The graph tolerates cycles (real npm graphs have
 * them via `peerDependencies`) and never recurses without a visited set.
 */
export class DependencyGraph {
  private readonly nodesById = new Map<string, DependencyNode>();
  private readonly outgoing = new Map<string, Set<string>>();
  private readonly incoming = new Map<string, Set<string>>();
  private readonly edgeKinds = new Map<string, Map<string, GraphEdge['kind']>>();

  static nodeId(ecosystem: string, name: string, version: string): string {
    return `${ecosystem}:${name}@${version}`;
  }

  get size(): number {
    return this.nodesById.size;
  }

  get edgeCount(): number {
    let count = 0;
    for (const targets of this.outgoing.values()) count += targets.size;
    return count;
  }

  addNode(node: DependencyNode): DependencyNode {
    const existing = this.nodesById.get(node.id);
    if (existing) {
      // Merge: keep the strongest classification (direct beats transitive,
      // prod beats dev) and the shallowest depth.
      existing.direct = existing.direct || node.direct;
      existing.dev = existing.dev && node.dev;
      existing.optional = existing.optional && node.optional;
      existing.peer = existing.peer && node.peer;
      existing.depth = Math.min(existing.depth, node.depth);
      if (!existing.license && node.license) existing.license = node.license;
      if (!existing.integrity && node.integrity) existing.integrity = node.integrity;
      if (!existing.resolved && node.resolved) existing.resolved = node.resolved;
      if (!existing.declaredRange && node.declaredRange) existing.declaredRange = node.declaredRange;
      if (!existing.scripts && node.scripts) existing.scripts = node.scripts;
      if (!existing.engines && node.engines) existing.engines = node.engines;
      if (node.deprecated) existing.deprecated = true;
      if (!existing.workspace && node.workspace) existing.workspace = node.workspace;
      if (!this.outgoing.has(node.id)) this.outgoing.set(node.id, new Set());
      if (!this.incoming.has(node.id)) this.incoming.set(node.id, new Set());
      return existing;
    }
    this.nodesById.set(node.id, node);
    if (!this.outgoing.has(node.id)) this.outgoing.set(node.id, new Set());
    if (!this.incoming.has(node.id)) this.incoming.set(node.id, new Set());
    return node;
  }

  hasNode(id: string): boolean {
    return this.nodesById.has(id);
  }

  getNode(id: string): DependencyNode | undefined {
    return this.nodesById.get(id);
  }

  addEdge(from: string, to: string, kind: GraphEdge['kind'] = 'prod'): void {
    if (!this.nodesById.has(from) || !this.nodesById.has(to)) return;
    const forward = this.outgoing.get(from) ?? new Set<string>();
    forward.add(to);
    this.outgoing.set(from, forward);

    const backward = this.incoming.get(to) ?? new Set<string>();
    backward.add(from);
    this.incoming.set(to, backward);

    const kinds = this.edgeKinds.get(from) ?? new Map<string, GraphEdge['kind']>();
    const previous = kinds.get(to);
    if (previous === undefined) {
      kinds.set(to, kind);
    } else if (previous !== kind && kind === 'prod') {
      // Prefer the strongest relationship when an edge is reachable both ways.
      kinds.set(to, 'prod');
    }
    this.edgeKinds.set(from, kinds);
  }

  edgeKind(from: string, to: string): GraphEdge['kind'] | undefined {
    return this.edgeKinds.get(from)?.get(to);
  }

  nodes(): DependencyNode[] {
    return [...this.nodesById.values()];
  }

  allNodes(): IterableIterator<DependencyNode> {
    return this.nodesById.values();
  }

  directDependencies(): DependencyNode[] {
    return this.nodes().filter((n) => n.direct);
  }

  dependenciesOf(id: string): DependencyNode[] {
    const targets = this.outgoing.get(id);
    if (!targets) return [];
    return [...targets].map((t) => this.nodesById.get(t)).filter((n): n is DependencyNode => !!n);
  }

  dependentsOf(id: string): DependencyNode[] {
    const sources = this.incoming.get(id);
    if (!sources) return [];
    return [...sources].map((s) => this.nodesById.get(s)).filter((n): n is DependencyNode => !!n);
  }

  /** Direct and transitive dependents (the "blast radius") of a node. */
  transitiveDependents(id: string, options: TraversalOptions = {}): DependencyNode[] {
    const maxNodes = options.maxNodes ?? DEFAULT_MAX_NODES;
    // Seed with the target so a cycle (`a -> b -> a`) cannot report the node as
    // its own dependent.
    const visited = new Set<string>([id]);
    const queue = [...(this.incoming.get(id) ?? [])];
    const result: DependencyNode[] = [];
    while (queue.length > 0 && result.length < maxNodes) {
      const current = queue.shift() as string;
      if (visited.has(current)) continue;
      visited.add(current);
      const node = this.nodesById.get(current);
      if (node) result.push(node);
      for (const next of this.incoming.get(current) ?? []) {
        if (!visited.has(next)) queue.push(next);
      }
    }
    return result;
  }

  /** All dependencies reachable from `id`, breadth-first. */
  transitiveDependencies(id: string, options: TraversalOptions = {}): DependencyNode[] {
    const maxNodes = options.maxNodes ?? DEFAULT_MAX_NODES;
    const maxDepth = options.maxDepth ?? Number.POSITIVE_INFINITY;
    const visited = new Set<string>([id]);
    const queue: Array<{ id: string; depth: number }> = [{ id, depth: 0 }];
    const result: DependencyNode[] = [];
    while (queue.length > 0 && result.length < maxNodes) {
      const current = queue.shift() as { id: string; depth: number };
      if (current.depth >= maxDepth) continue;
      for (const next of this.outgoing.get(current.id) ?? []) {
        if (visited.has(next)) continue;
        visited.add(next);
        const node = this.nodesById.get(next);
        if (node) result.push(node);
        queue.push({ id: next, depth: current.depth + 1 });
      }
    }
    return result;
  }

  /**
   * The shortest dependency path from any root (depth 0 node) to `targetId`.
   * Returns the path as node ids including both endpoints, or `undefined`.
   */
  shortestPath(targetId: string): string[] | undefined {
    if (!this.nodesById.has(targetId)) return undefined;
    const target = this.nodesById.get(targetId) as DependencyNode;
    if (target.depth === 0) return [targetId];

    // BFS backwards from the target. We prefer a depth-0 project root as the
    // terminus; when no root exists (bare graphs in tests/tools) we fall back
    // to the shallowest direct dependency.
    const parents = new Map<string, string>();
    const visited = new Set<string>([targetId]);
    const queue: string[] = [targetId];
    let root: string | undefined;
    let directFallback: string | undefined;
    while (queue.length > 0) {
      const current = queue.shift() as string;
      if (current !== targetId) {
        const node = this.nodesById.get(current);
        if (node) {
          if (node.depth === 0) {
            root = current;
            break;
          }
          if (directFallback === undefined && node.direct) directFallback = current;
        }
      }
      for (const parent of this.incoming.get(current) ?? []) {
        if (visited.has(parent)) continue;
        visited.add(parent);
        parents.set(parent, current);
        queue.push(parent);
      }
    }
    const terminus = root ?? directFallback;
    if (terminus === undefined) return undefined;
    const path = [terminus];
    let cursor = terminus;
    while (cursor !== targetId) {
      const next = parents.get(cursor);
      if (next === undefined) return undefined;
      path.push(next);
      cursor = next;
    }
    return path;
  }

  private rootFor(id: string): string | undefined {
    for (const parent of this.incoming.get(id) ?? []) {
      const node = this.nodesById.get(parent);
      if (node && (node.direct || node.depth === 0)) return parent;
    }
    return undefined;
  }

  /**
   * Enumerate simple paths from any root to `targetId`, bounded by `limit`.
   * Used to explain *how* a transitive package entered the project.
   */
  pathsTo(targetId: string, limit = 5, maxDepth = 25): string[][] {
    if (!this.nodesById.has(targetId)) return [];
    const results: string[][] = [];
    // Prefer paths from the project root so the output shows how a package
    // entered the project. Fall back to direct nodes when no root node exists.
    const all = this.nodes();
    const projectRoots = all.filter((node) => node.depth === 0);
    const roots = (projectRoots.length > 0 ? projectRoots : all.filter((node) => node.direct)).map(
      (node) => node.id,
    );
    for (const root of roots) {
      if (results.length >= limit) break;
      const stack: Array<{ id: string; path: string[]; seen: Set<string> }> = [
        { id: root, path: [root], seen: new Set([root]) },
      ];
      while (stack.length > 0 && results.length < limit) {
        const { id, path, seen } = stack.pop() as { id: string; path: string[]; seen: Set<string> };
        if (id === targetId) {
          results.push(path);
          continue;
        }
        if (path.length > maxDepth) continue;
        for (const next of this.outgoing.get(id) ?? []) {
          if (seen.has(next)) continue;
          const nextSeen = new Set(seen);
          nextSeen.add(next);
          stack.push({ id: next, path: [...path, next], seen: nextSeen });
        }
      }
    }
    // Shortest paths first for readability.
    results.sort((a, b) => a.length - b.length);
    return results.slice(0, limit);
  }

  /** Package names that resolve to more than one version. */
  duplicates(): Map<string, DependencyNode[]> {
    const byName = new Map<string, DependencyNode[]>();
    for (const node of this.nodesById.values()) {
      const key = `${node.ecosystem}:${node.name}`;
      const list = byName.get(key) ?? [];
      list.push(node);
      byName.set(key, list);
    }
    const duplicates = new Map<string, DependencyNode[]>();
    for (const [key, list] of byName) {
      const versions = new Set(list.map((n) => n.version));
      if (versions.size > 1) duplicates.set(key, list);
    }
    return duplicates;
  }

  stats(): GraphStats {
    let maxDepth = 0;
    let depthSum = 0;
    let directNodes = 0;
    let devNodes = 0;
    let optionalNodes = 0;
    const names = new Set<string>();
    for (const node of this.nodesById.values()) {
      maxDepth = Math.max(maxDepth, node.depth);
      depthSum += node.depth;
      if (node.direct) directNodes += 1;
      if (node.dev) devNodes += 1;
      if (node.optional) optionalNodes += 1;
      names.add(`${node.ecosystem}:${node.name}`);
    }
    const total = this.nodesById.size;
    return {
      totalNodes: total,
      directNodes,
      transitiveNodes: total - directNodes,
      devNodes,
      optionalNodes,
      maxDepth,
      averageDepth: total === 0 ? 0 : Number((depthSum / total).toFixed(2)),
      edgeCount: this.edgeCount,
      duplicateVersions: this.duplicates().size,
      packageCountByName: names.size,
    };
  }

  /** Serialize to a plain, JSON-safe structure for API/JSON report output. */
  toJSON(): { nodes: DependencyNode[]; edges: GraphEdge[] } {
    const edges: GraphEdge[] = [];
    for (const [from, targets] of this.outgoing) {
      for (const to of targets) {
        edges.push({ from, to, kind: this.edgeKind(from, to) ?? 'prod' });
      }
    }
    return { nodes: this.nodes(), edges };
  }
}
