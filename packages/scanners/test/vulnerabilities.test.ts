import { describe, expect, it } from 'vitest';
import type { Advisory } from '@deplyze/core';
import { advisoryQueriesFor, findingsFromMatches, vulnerabilityScanner } from '../src/index.js';
import { makeContext, makeNode } from '../../../test/helpers.js';

function advisory(overrides: Partial<Advisory> = {}): Advisory {
  return {
    id: 'GHSA-test-1111-2222',
    aliases: ['CVE-2024-9999'],
    package: 'lodash',
    ecosystem: 'npm',
    affectedRanges: ['<4.17.21'],
    affectedVersions: [],
    fixedVersions: ['4.17.21'],
    severity: 'high',
    cvss: 9.8,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    summary: 'Prototype pollution in lodash',
    references: ['https://example.com/ghsa'],
    source: 'osv',
    ...overrides,
  };
}

describe('advisoryQueriesFor', () => {
  it('builds one query per non-root node and skips non-npm ecosystems', () => {
    const context = makeContext({
      nodes: [makeNode({ name: 'lodash', version: '4.17.20', id: 'npm:lodash@4.17.20' })],
      edges: [['root:.', 'npm:lodash@4.17.20']],
    });
    const queries = advisoryQueriesFor(context);
    expect(queries).toEqual([{ name: 'lodash', version: '4.17.20', ecosystem: 'npm' }]);
  });
});

describe('findingsFromMatches', () => {
  function contextWithNode() {
    const node = makeNode({ name: 'lodash', version: '4.17.20', direct: true, id: 'npm:lodash@4.17.20' });
    const context = makeContext({ nodes: [node], edges: [['root:.', 'npm:lodash@4.17.20']] });
    return { context, node };
  }

  it('builds an evidence-backed vulnerability finding with a fix', () => {
    const { context, node } = contextWithNode();
    const [finding] = findingsFromMatches(context, [
      { node, advisory: advisory(), matchedOn: '<4.17.21', fixedVersion: '4.17.21' },
    ]);
    expect(finding?.category).toBe('vulnerability');
    expect(finding?.severity).toBe('high');
    expect(finding?.advisoryId).toBe('GHSA-test-1111-2222');
    expect(finding?.title).toContain('Prototype pollution');
    expect(finding?.remediation?.command).toBe('npm install lodash@^4.17.21');
    expect(finding?.evidence.some((entry) => entry.kind === 'fixed-version')).toBe(true);
    expect(finding?.evidence.some((entry) => entry.kind === 'cvss')).toBe(true);
    expect(finding?.paths?.length).toBeGreaterThan(0);
  });

  it('honours the allowedAdvisories suppression list', () => {
    const { context, node } = contextWithNode();
    context.config.security.vulnerabilities.allowedAdvisories = ['GHSA-test-1111-2222'];
    expect(findingsFromMatches(context, [{ node, advisory: advisory(), matchedOn: '<4.17.21' }])).toEqual([]);
  });

  it('explains when no fixed version is published', () => {
    const { context, node } = contextWithNode();
    const [finding] = findingsFromMatches(context, [
      { node, advisory: advisory({ fixedVersions: [] }), matchedOn: '<4.17.21' },
    ]);
    expect(finding?.remediation?.command).toBeUndefined();
    expect(finding?.remediation?.summary).toContain('No fixed version');
  });

  it('describes transitive exposure without overstating reachability', () => {
    const node = makeNode({ name: 'lodash', version: '4.17.20', depth: 2, id: 'npm:lodash@4.17.20' });
    const context = makeContext({ nodes: [node], edges: [['root:.', 'npm:lodash@4.17.20']] });
    const [finding] = findingsFromMatches(context, [{ node, advisory: advisory(), matchedOn: '<4.17.21' }]);
    expect(finding?.description).toContain('transitively');
  });
});

describe('vulnerabilityScanner', () => {
  it('matches pre-fetched advisories against the graph', async () => {
    const node = makeNode({ name: 'lodash', version: '4.17.20', direct: true, id: 'npm:lodash@4.17.20' });
    const context = makeContext({ nodes: [node], edges: [['root:.', 'npm:lodash@4.17.20']] });
    context.advisoryResult = {
      advisories: [advisory()],
      unresolved: [],
      usedNetwork: true,
      usedCache: false,
    };
    const findings = await vulnerabilityScanner.run(context);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.package).toBe('lodash');
  });

  it('returns nothing when advisories are disabled', async () => {
    const node = makeNode({ name: 'lodash', version: '4.17.20', direct: true, id: 'npm:lodash@4.17.20' });
    const context = makeContext({ nodes: [node], edges: [['root:.', 'npm:lodash@4.17.20']] });
    context.config.advisories.enabled = false;
    expect(await vulnerabilityScanner.run(context)).toEqual([]);
  });
});
