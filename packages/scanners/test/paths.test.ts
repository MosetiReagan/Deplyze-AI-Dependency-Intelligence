import { describe, expect, it } from 'vitest';
import { countDependents, dependencyPaths, formatPath, nodeLabel } from '../src/index.js';
import { makeContext } from '../../../test/helpers.js';

const context = makeContext();
const graph = context.graph;

describe('nodeLabel', () => {
  it('labels roots, packages and unknown ids', () => {
    expect(nodeLabel(graph.getNode('root:.'), 'root:.')).toContain('(project)');
    expect(nodeLabel(graph.getNode('npm:lodash@4.17.20'), 'npm:lodash@4.17.20')).toBe('lodash@4.17.20');
    expect(nodeLabel(undefined, 'npm:missing@1.0.0')).toBe('npm:missing@1.0.0');
  });
});

describe('dependencyPaths', () => {
  it('renders a path from the project root and names the introducer', () => {
    const paths = dependencyPaths(graph, 'npm:minimist@1.2.0');
    expect(paths.length).toBeGreaterThan(0);
    expect(paths[0]?.formatted).toContain('fixture-app');
    expect(paths[0]?.formatted).toContain('minimist@1.2.0');
    expect(paths[0]?.introducedBy).toBe('lodash@4.17.20');
  });

  it('formatPath joins labels with an arrow', () => {
    expect(formatPath(graph, ['root:.', 'npm:lodash@4.17.20'])).toContain(' > ');
  });
});

describe('countDependents', () => {
  it('counts transitive dependents', () => {
    expect(countDependents(graph, 'npm:minimist@1.2.0')).toBe(2);
    expect(countDependents(graph, 'npm:lodash@4.17.20')).toBe(1);
  });
});
