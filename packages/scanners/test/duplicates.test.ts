import { describe, expect, it } from 'vitest';
import { makeContext } from '../../../test/helpers.js';
import type { DependencyNode } from '@deplyze/core';
import { duplicateScanner } from '../src/index.js';

function graphContext(nodes: DependencyNode[], edges: Array<[string, string]>) {
  return makeContext({ nodes, edges });
}

const root: DependencyNode = {
  id: 'root:.',
  name: 'app',
  version: '1.0.0',
  ecosystem: 'npm',
  direct: false,
  dev: false,
  optional: false,
  peer: false,
  depth: 0,
  dependencies: [],
};

describe('duplicateScanner', () => {
  it('reports two major versions with their paths', async () => {
    const context = graphContext(
      [
        root,
        {
          id: 'npm:react@17.0.2',
          name: 'react',
          version: '17.0.2',
          ecosystem: 'npm',
          direct: true,
          dev: false,
          optional: false,
          peer: false,
          depth: 1,
          dependencies: [],
        },
        {
          id: 'npm:react@18.2.0',
          name: 'react',
          version: '18.2.0',
          ecosystem: 'npm',
          direct: false,
          dev: false,
          optional: false,
          peer: false,
          depth: 2,
          dependencies: [],
        },
      ],
      [
        ['root:.', 'npm:react@17.0.2'],
        ['root:.', 'npm:react@18.2.0'],
      ],
    );
    const findings = await duplicateScanner.run(context);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.severity).toBe('medium');
    expect(findings[0]?.title).toContain('react');
    expect(findings[0]?.title).toContain('18.2.0');
    expect(findings[0]?.evidence.some((entry) => entry.kind === 'versions')).toBe(true);
  });

  it('rates same-major duplicates as low severity', async () => {
    const context = graphContext(
      [
        root,
        {
          id: 'npm:lodash@4.17.20',
          name: 'lodash',
          version: '4.17.20',
          ecosystem: 'npm',
          direct: true,
          dev: false,
          optional: false,
          peer: false,
          depth: 1,
          dependencies: [],
        },
        {
          id: 'npm:lodash@4.17.21',
          name: 'lodash',
          version: '4.17.21',
          ecosystem: 'npm',
          direct: false,
          dev: false,
          optional: false,
          peer: false,
          depth: 2,
          dependencies: [],
        },
      ],
      [
        ['root:.', 'npm:lodash@4.17.20'],
        ['root:.', 'npm:lodash@4.17.21'],
      ],
    );
    const findings = await duplicateScanner.run(context);
    expect(findings[0]?.severity).toBe('low');
  });

  it('reports nothing for a single version', async () => {
    const context = graphContext(
      [
        root,
        {
          id: 'npm:lodash@4.17.21',
          name: 'lodash',
          version: '4.17.21',
          ecosystem: 'npm',
          direct: true,
          dev: false,
          optional: false,
          peer: false,
          depth: 1,
          dependencies: [],
        },
      ],
      [['root:.', 'npm:lodash@4.17.21']],
    );
    expect(await duplicateScanner.run(context)).toEqual([]);
  });
});
