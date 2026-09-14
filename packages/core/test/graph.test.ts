import { describe, expect, it } from 'vitest';
import { DependencyGraph, type DependencyNode } from '../src/index.js';

function node(
  overrides: Partial<DependencyNode> & { id: string; name: string; version: string },
): DependencyNode {
  return {
    ecosystem: 'npm',
    direct: false,
    dev: false,
    optional: false,
    peer: false,
    depth: 1,
    dependencies: [],
    ...overrides,
  };
}

function buildGraph(): DependencyGraph {
  const graph = new DependencyGraph();
  graph.addNode(node({ id: 'root:.', name: 'app', version: '1.0.0', depth: 0 }));
  graph.addNode(node({ id: 'npm:a@1.0.0', name: 'a', version: '1.0.0', direct: true }));
  graph.addNode(node({ id: 'npm:b@1.0.0', name: 'b', version: '1.0.0', direct: true, dev: true }));
  graph.addNode(node({ id: 'npm:c@1.0.0', name: 'c', version: '1.0.0', depth: 2 }));
  graph.addNode(node({ id: 'npm:d@1.0.0', name: 'd', version: '1.0.0', depth: 3 }));
  graph.addNode(node({ id: 'npm:a@2.0.0', name: 'a', version: '2.0.0', depth: 2 }));
  graph.addEdge('root:.', 'npm:a@1.0.0', 'prod');
  graph.addEdge('root:.', 'npm:b@1.0.0', 'dev');
  graph.addEdge('npm:a@1.0.0', 'npm:c@1.0.0', 'prod');
  graph.addEdge('npm:c@1.0.0', 'npm:d@1.0.0', 'prod');
  graph.addEdge('npm:b@1.0.0', 'npm:a@2.0.0', 'dev');
  return graph;
}

describe('DependencyGraph', () => {
  it('counts nodes and edges', () => {
    const graph = buildGraph();
    expect(graph.size).toBe(6);
    expect(graph.edgeCount).toBe(5);
  });

  it('merges duplicate node ids without losing the strongest classification', () => {
    const graph = new DependencyGraph();
    graph.addNode(node({ id: 'npm:x@1.0.0', name: 'x', version: '1.0.0', dev: true, depth: 3 }));
    graph.addNode(
      node({
        id: 'npm:x@1.0.0',
        name: 'x',
        version: '1.0.0',
        dev: false,
        direct: true,
        depth: 1,
        license: 'MIT',
      }),
    );
    expect(graph.size).toBe(1);
    const merged = graph.getNode('npm:x@1.0.0');
    expect(merged?.direct).toBe(true);
    expect(merged?.dev).toBe(false);
    expect(merged?.depth).toBe(1);
    expect(merged?.license).toBe('MIT');
  });

  it('finds transitive dependents (blast radius)', () => {
    const graph = buildGraph();
    const dependents = graph.transitiveDependents('npm:d@1.0.0').map((entry) => entry.name);
    expect(dependents.sort()).toEqual(['a', 'c', 'app'].sort());
  });

  it('finds transitive dependencies', () => {
    const graph = buildGraph();
    const deps = graph
      .transitiveDependencies('npm:a@1.0.0')
      .map((entry) => entry.id)
      .sort();
    expect(deps).toEqual(['npm:c@1.0.0', 'npm:d@1.0.0']);
  });

  it('returns full dependency paths from the project root', () => {
    const graph = buildGraph();
    const paths = graph.pathsTo('npm:d@1.0.0');
    expect(paths.length).toBeGreaterThan(0);
    expect(paths[0]).toEqual(['root:.', 'npm:a@1.0.0', 'npm:c@1.0.0', 'npm:d@1.0.0']);
  });

  it('reports a shortest path', () => {
    const graph = buildGraph();
    expect(graph.shortestPath('npm:d@1.0.0')).toEqual([
      'root:.',
      'npm:a@1.0.0',
      'npm:c@1.0.0',
      'npm:d@1.0.0',
    ]);
  });

  it('detects duplicate versions', () => {
    const graph = buildGraph();
    const duplicates = graph.duplicates();
    expect([...duplicates.keys()]).toEqual(['npm:a']);
    expect(duplicates.get('npm:a')?.length).toBe(2);
  });

  it('computes statistics', () => {
    const graph = buildGraph();
    const stats = graph.stats();
    expect(stats.totalNodes).toBe(6);
    expect(stats.directNodes).toBe(2);
    expect(stats.transitiveNodes).toBe(4);
    expect(stats.maxDepth).toBe(3);
    expect(stats.duplicateVersions).toBe(1);
  });

  it('terminates on cyclic graphs', () => {
    const graph = new DependencyGraph();
    graph.addNode(node({ id: 'root:.', name: 'app', version: '1.0.0', depth: 0 }));
    graph.addNode(node({ id: 'npm:a@1.0.0', name: 'a', version: '1.0.0', direct: true }));
    graph.addNode(node({ id: 'npm:b@1.0.0', name: 'b', version: '1.0.0', depth: 2 }));
    graph.addEdge('root:.', 'npm:a@1.0.0');
    graph.addEdge('npm:a@1.0.0', 'npm:b@1.0.0');
    graph.addEdge('npm:b@1.0.0', 'npm:a@1.0.0');
    expect(graph.transitiveDependencies('npm:a@1.0.0').length).toBe(1);
    expect(graph.transitiveDependents('npm:a@1.0.0').length).toBe(2);
  });

  it('ignores edges to unknown nodes', () => {
    const graph = new DependencyGraph();
    graph.addNode(node({ id: 'npm:a@1.0.0', name: 'a', version: '1.0.0' }));
    graph.addEdge('npm:a@1.0.0', 'npm:missing@1.0.0');
    expect(graph.edgeCount).toBe(0);
  });

  it('serializes to a JSON-safe structure', () => {
    const graph = buildGraph();
    const json = graph.toJSON();
    expect(json.nodes.length).toBe(6);
    expect(json.edges.length).toBe(5);
    expect(JSON.parse(JSON.stringify(json)).nodes.length).toBe(6);
  });
});
