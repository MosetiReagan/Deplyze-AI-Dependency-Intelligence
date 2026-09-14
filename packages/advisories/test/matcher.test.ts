import { describe, expect, it } from 'vitest';
import { makeNode } from '../../../test/helpers.js';
import type { Advisory } from '@deplyze/core';
import { advisoryAppliesTo, matchAdvisories } from '../src/index.js';

function advisory(overrides: Partial<Advisory> = {}): Advisory {
  return {
    id: 'GHSA-aaaa-bbbb-cccc',
    aliases: [],
    package: 'lodash',
    ecosystem: 'npm',
    affectedRanges: [],
    affectedVersions: [],
    fixedVersions: [],
    summary: 'Example advisory',
    references: [],
    source: 'osv',
    ...overrides,
  };
}

describe('advisoryAppliesTo', () => {
  it('matches an explicit version list and selects the nearest fixed version', () => {
    const result = advisoryAppliesTo(
      advisory({ affectedVersions: ['1.0.0'], fixedVersions: ['2.0.0', '1.0.1'] }),
      '1.0.0',
    );
    expect(result.applies).toBe(true);
    expect(result.fixedVersion).toBe('1.0.1');
    expect(result.matchedOn).toContain('explicit version list');
  });

  it('matches ranges and reports the range that matched', () => {
    const result = advisoryAppliesTo(advisory({ affectedRanges: ['>=1.0.0 <1.5.0'] }), '1.2.0');
    expect(result.applies).toBe(true);
    expect(result.matchedOn).toBe('>=1.0.0 <1.5.0');
  });

  it('does not match a version outside every range', () => {
    expect(advisoryAppliesTo(advisory({ affectedRanges: ['>=1.0.0 <1.5.0'] }), '2.0.0').applies).toBe(false);
  });

  it('ignores fixes older than the installed version', () => {
    const result = advisoryAppliesTo(advisory({ affectedRanges: ['*'], fixedVersions: ['0.9.0'] }), '1.0.0');
    expect(result.applies).toBe(true);
    expect(result.fixedVersion).toBeUndefined();
  });
});

describe('matchAdvisories', () => {
  const nodes = [
    makeNode({ name: 'root', version: '1.0.0', depth: 0, id: 'root:.' }),
    makeNode({ name: 'lodash', version: '4.17.20', direct: true }),
    makeNode({ name: 'minimist', version: '1.2.0', depth: 2 }),
  ];

  it('only returns matches for the right package, version and ecosystem', () => {
    const matches = matchAdvisories(nodes, [
      advisory({ package: 'lodash', affectedRanges: ['<4.17.21'], fixedVersions: ['4.17.21'] }),
      advisory({ id: 'GHSA-other', package: 'lodash', affectedRanges: ['>=5.0.0'] }),
      advisory({ id: 'GHSA-minimist', package: 'minimist', affectedRanges: ['*'] }),
    ]);
    expect(matches.map((match) => match.advisory.id)).toEqual(['GHSA-aaaa-bbbb-cccc', 'GHSA-minimist']);
  });

  it('never matches the project root node', () => {
    const matches = matchAdvisories(nodes, [advisory({ package: 'root', affectedRanges: ['*'] })]);
    expect(matches).toHaveLength(0);
  });

  it('requireApplicableFix drops advisories already fixed at the installed version', () => {
    const matches = matchAdvisories(
      nodes,
      [
        advisory({
          package: 'lodash',
          affectedRanges: ['<4.17.21'],
          fixedVersions: ['4.17.21'],
        }),
        advisory({
          id: 'GHSA-fixed',
          package: 'lodash',
          affectedRanges: ['<4.17.20'],
          fixedVersions: ['4.17.20'],
        }),
      ],
      { requireApplicableFix: true },
    );
    expect(matches.map((match) => match.advisory.id)).toEqual(['GHSA-aaaa-bbbb-cccc']);
  });

  it('attaches the matched node so callers can build dependency paths', () => {
    const matches = matchAdvisories(nodes, [advisory({ package: 'lodash', affectedRanges: ['<4.17.21'] })]);
    expect(matches[0]?.node.id).toBe('npm:lodash@4.17.20');
    expect(matches[0]?.matchedOn).toBe('<4.17.21');
  });
});
