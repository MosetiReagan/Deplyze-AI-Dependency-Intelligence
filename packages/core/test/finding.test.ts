import { describe, expect, it } from 'vitest';
import { createFinding, dedupeFindings, sortFindings, summarize } from '../src/index.js';

const base = {
  category: 'vulnerability' as const,
  severity: 'high' as const,
  confidence: 'high' as const,
  title: 'Example advisory',
  description: 'Something is wrong.',
  source: 'security/vulnerability',
};

describe('createFinding', () => {
  it('produces a stable id for the same identity', () => {
    const a = createFinding({ ...base, package: 'lodash', version: '4.17.15', advisoryId: 'GHSA-x' });
    const b = createFinding({ ...base, package: 'lodash', version: '4.17.15', advisoryId: 'GHSA-x' });
    expect(a.id).toBe(b.id);
    expect(a.id).toMatch(/^DEP-[0-9A-F]{10}$/);
  });

  it('produces different ids for different packages', () => {
    const a = createFinding({ ...base, package: 'lodash', version: '4.17.15' });
    const b = createFinding({ ...base, package: 'minimist', version: '4.17.15' });
    expect(a.id).not.toBe(b.id);
  });

  it('honours an explicit stable id', () => {
    const finding = createFinding({ ...base, package: 'x', version: '1.0.0', stableId: 'rule|pkg|1.0.0' });
    const other = createFinding({ ...base, package: 'y', version: '9.9.9', stableId: 'rule|pkg|1.0.0' });
    expect(finding.id).toBe(other.id);
  });
});

describe('dedupeFindings', () => {
  it('merges evidence and keeps the highest severity', () => {
    const first = createFinding({
      ...base,
      package: 'a',
      version: '1.0.0',
      evidence: [{ kind: 'x', message: 'one' }],
    });
    const second = createFinding({
      ...base,
      severity: 'critical',
      package: 'a',
      version: '1.0.0',
      evidence: [
        { kind: 'x', message: 'one' },
        { kind: 'y', message: 'two' },
      ],
    });
    const merged = dedupeFindings([first, second]);
    expect(merged).toHaveLength(1);
    expect(merged[0]?.severity).toBe('critical');
    expect(merged[0]?.evidence).toHaveLength(2);
  });
});

describe('sortFindings', () => {
  it('orders by severity then package', () => {
    const findings = [
      createFinding({ ...base, severity: 'low', package: 'b', version: '1.0.0' }),
      createFinding({ ...base, severity: 'critical', package: 'z', version: '1.0.0' }),
      createFinding({ ...base, severity: 'critical', package: 'a', version: '1.0.0' }),
    ];
    const sorted = sortFindings(findings);
    expect(sorted.map((finding) => `${finding.severity}:${finding.package}`)).toEqual([
      'critical:a',
      'critical:z',
      'low:b',
    ]);
  });
});

describe('summarize', () => {
  it('counts by severity and category', () => {
    const findings = [
      createFinding({ ...base, severity: 'critical', package: 'a', version: '1' }),
      createFinding({ ...base, severity: 'high', package: 'b', version: '1' }),
      createFinding({ ...base, category: 'license', severity: 'low', package: 'c', version: '1' }),
    ];
    const summary = summarize(findings);
    expect(summary.total).toBe(3);
    expect(summary.critical).toBe(1);
    expect(summary.byCategory.vulnerability).toBe(2);
    expect(summary.byCategory.license).toBe(1);
  });
});
