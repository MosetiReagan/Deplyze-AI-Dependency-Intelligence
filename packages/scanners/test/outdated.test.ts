import { describe, expect, it } from 'vitest';
import { computeOutdated, lagLabel, outdatedScanner, type RegistryMetadata } from '../src/index.js';
import { makeContext, makeNode } from '../../../test/helpers.js';

function meta(name: string, latest: string, time: Record<string, string> = {}): RegistryMetadata {
  return {
    name,
    latest,
    versions: [{ version: latest }],
    time,
    fromCache: false,
    fetchedAt: '2025-01-01T00:00:00.000Z',
  };
}

describe('lagLabel', () => {
  it('labels every lag kind', () => {
    expect(lagLabel('major')).toBe('Major behind');
    expect(lagLabel('minor')).toBe('Minor behind');
    expect(lagLabel('equal')).toBe('Up to date');
  });
});

describe('computeOutdated', () => {
  it('classifies major, minor and patch drift', () => {
    const nodes = [
      makeNode({ name: 'a', version: '1.0.0', direct: true }),
      makeNode({ name: 'b', version: '1.0.0', direct: true }),
      makeNode({ name: 'c', version: '1.0.1', direct: true }),
    ];
    const metadata = new Map([
      ['a', meta('a', '2.0.0')],
      ['b', meta('b', '1.1.0')],
      ['c', meta('c', '1.0.2')],
    ]);
    const entries = computeOutdated(nodes, metadata, { now: new Date('2025-01-01T00:00:00Z') });
    expect(entries.map((entry) => `${entry.node.name}:${entry.lag}`).sort()).toEqual([
      'a:major',
      'b:minor',
      'c:patch',
    ]);
  });

  it('skips packages that are up to date or unknown', () => {
    const nodes = [
      makeNode({ name: 'a', version: '1.0.0', direct: true }),
      makeNode({ name: 'b', version: '1.0.0', direct: true }),
    ];
    const metadata = new Map([['a', meta('a', '1.0.0')]]);
    expect(computeOutdated(nodes, metadata)).toEqual([]);
  });

  it('computes release ages in months', () => {
    const nodes = [makeNode({ name: 'a', version: '1.0.0', direct: true })];
    const metadata = new Map([
      ['a', meta('a', '2.0.0', { '1.0.0': '2023-01-01T00:00:00Z', '2.0.0': '2024-01-01T00:00:00Z' })],
    ]);
    const entry = computeOutdated(nodes, metadata, { now: new Date('2025-01-01T00:00:00Z') })[0];
    expect(entry?.installedAgeMonths).toBeGreaterThan(23);
    expect(entry?.latestAgeMonths).toBeGreaterThan(11);
  });
});

describe('outdatedScanner', () => {
  it('reports a major upgrade for a direct dependency with breaking-change guidance', async () => {
    const context = makeContext({
      nodes: [
        makeNode({
          name: 'lodash',
          version: '3.0.0',
          direct: true,
          declaredRange: '^3.0.0',
          id: 'npm:lodash@3.0.0',
        }),
      ],
      edges: [['root:.', 'npm:lodash@3.0.0']],
      metadata: new Map([['lodash', meta('lodash', '4.17.21')]]),
    });
    const findings = await outdatedScanner.run(context);
    const finding = findings.find((entry) => entry.package === 'lodash');
    expect(finding?.severity).toBe('medium');
    expect(finding?.remediation?.command).toContain('lodash@4.17.21');
    expect(finding?.remediation?.upgrades?.[0]?.breaking).toBe(true);
    expect(finding?.remediation?.steps?.length).toBeGreaterThan(0);
  });

  it('reports minor drift for direct dependencies without claiming breakage', async () => {
    const context = makeContext({
      nodes: [makeNode({ name: 'lodash', version: '4.16.0', direct: true, id: 'npm:lodash@4.16.0' })],
      edges: [['root:.', 'npm:lodash@4.16.0']],
      metadata: new Map([['lodash', meta('lodash', '4.17.21')]]),
    });
    const finding = (await outdatedScanner.run(context))[0];
    expect(finding?.severity).toBe('low');
    expect(finding?.remediation?.upgrades?.[0]?.breaking).toBe(false);
  });

  it('reports major drift for transitive dependencies (with a path to the introducer)', async () => {
    const context = makeContext({
      nodes: [
        makeNode({ name: 'framework', version: '1.0.0', direct: true, id: 'npm:framework@1.0.0' }),
        makeNode({ name: 'util', version: '1.0.0', depth: 2, id: 'npm:util@1.0.0' }),
      ],
      edges: [
        ['root:.', 'npm:framework@1.0.0'],
        ['npm:framework@1.0.0', 'npm:util@1.0.0'],
      ],
      metadata: new Map([
        ['framework', meta('framework', '1.0.0')],
        ['util', meta('util', '2.0.0')],
      ]),
    });
    const findings = await outdatedScanner.run(context);
    expect(findings.map((finding) => finding.package)).toContain('util');
  });

  it('ignores transitive minor drift as non-actionable', async () => {
    const context = makeContext({
      nodes: [makeNode({ name: 'util', version: '1.0.0', depth: 2, id: 'npm:util@1.0.0' })],
      edges: [['root:.', 'npm:util@1.0.0']],
      metadata: new Map([['util', meta('util', '1.1.0')]]),
    });
    expect(await outdatedScanner.run(context)).toEqual([]);
  });

  it('skips dev dependencies when includeDev is false', async () => {
    const context = makeContext({
      nodes: [makeNode({ name: 'tool', version: '1.0.0', direct: true, dev: true, id: 'npm:tool@1.0.0' })],
      edges: [['root:.', 'npm:tool@1.0.0']],
      metadata: new Map([['tool', meta('tool', '2.0.0')]]),
    });
    context.config.scan.includeDev = false;
    expect(await outdatedScanner.run(context)).toEqual([]);
  });

  it('includes dev dependencies by default', async () => {
    const context = makeContext({
      nodes: [makeNode({ name: 'tool', version: '1.0.0', direct: true, dev: true, id: 'npm:tool@1.0.0' })],
      edges: [['root:.', 'npm:tool@1.0.0']],
      metadata: new Map([['tool', meta('tool', '2.0.0')]]),
    });
    expect((await outdatedScanner.run(context)).length).toBe(1);
  });
});
