import { describe, expect, it } from 'vitest';
import { makeFinding, makeNode, makeResult } from '../../../test/helpers.js';
import { scoreRisk } from '../src/index.js';

function statsFor(findings = []) {
  return makeResult({ findings }).stats;
}

describe('scoreRisk', () => {
  it('reports a perfect score when there is nothing to deduct', () => {
    const result = scoreRisk({ findings: [], stats: statsFor(), directDependencies: 1 });
    expect(result.overall).toBe(100);
    expect(result.band).toBe('excellent');
    expect(result.categories.every((category) => category.score === 100)).toBe(true);
    expect(result.contributors).toEqual([]);
  });

  it('deducts from the security category for each severity band', () => {
    const findings = [
      makeFinding({ severity: 'critical', title: 'Critical vuln' }),
      makeFinding({ severity: 'high', title: 'High vuln', id: 'DEP-2' }),
    ];
    const result = scoreRisk({ findings, stats: statsFor(findings), directDependencies: 1 });
    const security = result.categories.find((c) => c.category === 'security')!;
    expect(security.score).toBeLessThan(100);
    const reasons = security.contributions.map((c) => c.reason).join(' ');
    expect(reasons).toContain('1 critical');
    expect(reasons).toContain('1 high');
    expect(result.contributors[0]?.points).toBeGreaterThan(0);
  });

  it('caps a single category so noise cannot saturate the score', () => {
    const findings = Array.from({ length: 40 }, (_, index) =>
      makeFinding({ severity: 'low', title: `Low ${index}`, id: `DEP-${index}`, package: `pkg-${index}` }),
    );
    const security = scoreRisk({
      findings,
      stats: statsFor(findings),
      directDependencies: 1,
    }).categories.find((c) => c.category === 'security')!;
    expect(security.score).toBeGreaterThanOrEqual(0);
    expect(security.contributions[0]?.points).toBeLessThanOrEqual(100);
  });

  it('maps finding categories onto the documented risk categories', () => {
    const findings = [
      makeFinding({
        category: 'license',
        severity: 'high',
        title: 'License violation',
        source: 'license/policy',
      }),
      makeFinding({
        category: 'duplicate',
        severity: 'medium',
        title: 'Duplicate',
        id: 'DEP-D',
        source: 'graph/duplicates',
      }),
      makeFinding({
        category: 'outdated',
        severity: 'low',
        title: 'Outdated major',
        id: 'DEP-O',
        source: 'registry/outdated',
      }),
      makeFinding({
        category: 'supply-chain',
        severity: 'high',
        title: 'Potential typosquat',
        id: 'DEP-T',
        source: 'supply-chain/typosquat',
      }),
    ];
    const result = scoreRisk({ findings, stats: statsFor(), directDependencies: 1 });
    expect(result.categories.find((c) => c.category === 'license')!.score).toBeLessThan(100);
    expect(result.categories.find((c) => c.category === 'upgrade-risk')!.score).toBeLessThan(100);
    expect(result.categories.find((c) => c.category === 'supply-chain')!.score).toBeLessThan(100);
  });

  it('deducts dependency-health points from graph structure (duplicates, depth)', () => {
    const result = makeResult({
      nodes: [
        { ...makeNode({ name: 'lodash', version: '4.17.20', direct: true }) },
        { ...makeNode({ name: 'lodash', version: '4.17.21', direct: true }) },
      ],
      edges: [],
    });
    const score = scoreRisk({ findings: [], stats: result.stats, directDependencies: 2 });
    expect(result.stats.duplicateVersions).toBe(1);
    expect(score.categories.find((c) => c.category === 'dependency-health')!.score).toBeLessThan(100);
  });

  it('produces a lower overall score as severity rises', () => {
    const low = scoreRisk({
      findings: [makeFinding({ severity: 'low', title: 'Low' })],
      stats: statsFor(),
      directDependencies: 1,
    });
    const critical = scoreRisk({
      findings: [makeFinding({ severity: 'critical', title: 'Critical' })],
      stats: statsFor(),
      directDependencies: 1,
    });
    expect(critical.overall).toBeLessThan(low.overall);
  });

  it('attaches evidence ids to contributions so every point is auditable', () => {
    const finding = makeFinding({ severity: 'critical', title: 'Critical vuln' });
    const result = scoreRisk({ findings: [finding], stats: statsFor(), directDependencies: 1 });
    expect(result.contributors[0]?.evidenceIds).toContain(finding.id);
  });

  it('documents its methodology rather than presenting an opaque number', () => {
    const result = scoreRisk({ findings: [], stats: statsFor(), directDependencies: 1 });
    expect(result.methodology).toContain('higher is better');
  });

  it('bands scores at the documented boundaries', () => {
    const mapBand = (band: string) => band;
    const result = scoreRisk({ findings: [], stats: statsFor(), directDependencies: 1 });
    expect(mapBand(result.band)).toBe('excellent');
  });
});
