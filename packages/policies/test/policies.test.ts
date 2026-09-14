import { describe, expect, it } from 'vitest';
import { EXIT } from '@deplyze/core';
import { resolveConfig } from '@deplyze/config';
import { makeFinding, makeResult } from '../../../test/helpers.js';
import { applySuppressions, evaluatePolicy, formatViolations } from '../src/index.js';

const highFinding = makeFinding({
  severity: 'high',
  title: 'High vuln',
  id: 'DEP-HIGH',
  advisoryId: 'GHSA-aaaa-bbbb-cccc',
});

describe('applySuppressions', () => {
  it('suppresses a finding by stable id', () => {
    const config = resolveConfig({ ignore: [{ id: 'DEP-HIGH', reason: 'accepted' }] });
    const outcome = applySuppressions([highFinding], config);
    expect(outcome.active).toEqual([]);
    expect(outcome.suppressed).toHaveLength(1);
  });

  it('suppresses a finding by advisory id and alias', () => {
    const config = resolveConfig({ ignore: [{ id: 'GHSA-aaaa-bbbb-cccc', reason: 'accepted' }] });
    expect(applySuppressions([highFinding], config).active).toEqual([]);
  });

  it('never lets an expired suppression silence a finding', () => {
    const config = resolveConfig({
      ignore: [{ id: 'DEP-HIGH', reason: 'accepted', expires: '2020-01-01' }],
    });
    const outcome = applySuppressions([highFinding], config, new Date('2025-01-01T00:00:00Z'));
    expect(outcome.active).toHaveLength(1);
    expect(outcome.expired).toHaveLength(1);
  });

  it('treats a malformed expiry as expired (fail loudly)', () => {
    const config = resolveConfig({ ignore: [{ id: 'DEP-HIGH', reason: 'accepted', expires: 'not-a-date' }] });
    expect(applySuppressions([highFinding], config).active).toHaveLength(1);
  });

  it('reports suppressions that matched nothing as unused', () => {
    const config = resolveConfig({ ignore: [{ id: 'DEP-NOPE', reason: 'stale' }] });
    const outcome = applySuppressions([highFinding], config);
    expect(outcome.unused).toHaveLength(1);
    expect(outcome.active).toHaveLength(1);
  });

  it('scopes a suppression to a package when requested', () => {
    const other = makeFinding({ severity: 'high', title: 'Other', id: 'DEP-HIGH', package: 'other' });
    const config = resolveConfig({ ignore: [{ id: 'DEP-HIGH', reason: 'accepted', package: 'lodash' }] });
    const outcome = applySuppressions([highFinding, other], config);
    expect(outcome.active.map((finding) => finding.package)).toEqual(['other']);
  });
});

describe('evaluatePolicy', () => {
  it('passes a clean project with exit code 0', () => {
    const result = makeResult({ findings: [] });
    const evaluation = evaluatePolicy(result);
    expect(evaluation.passed).toBe(true);
    expect(evaluation.exitCode).toBe(EXIT.PASS);
  });

  it('fails on a finding at or above the configured severity threshold', () => {
    const config = resolveConfig({ security: { failOn: ['high'] } });
    const result = makeResult({ findings: [highFinding], config });
    const evaluation = evaluatePolicy(result);
    expect(evaluation.passed).toBe(false);
    expect(evaluation.exitCode).toBe(EXIT.POLICY_VIOLATION);
    expect(evaluation.violations.map((violation) => violation.rule)).toContain('security.failOn:high');
  });

  it('does not fail on a low finding when only high is configured', () => {
    const config = resolveConfig({ security: { failOn: ['high'] } });
    const result = makeResult({ findings: [makeFinding({ severity: 'low' })], config });
    expect(evaluatePolicy(result).passed).toBe(true);
  });

  it('enforces vulnerability count ceilings', () => {
    const config = resolveConfig({ security: { failOn: [], vulnerabilities: { maxHigh: 0 } } });
    const result = makeResult({ findings: [highFinding], config });
    const evaluation = evaluatePolicy(result);
    expect(evaluation.violations.map((violation) => violation.rule)).toContain(
      'security.vulnerabilities.maxHigh',
    );
  });

  it('enforces license denial policy', () => {
    const config = resolveConfig({ licenses: { denied: ['AGPL-3.0'] } });
    const finding = makeFinding({
      category: 'license',
      severity: 'high',
      source: 'license/policy',
      title: 'License policy violation: AGPL-3.0',
    });
    const evaluation = evaluatePolicy(makeResult({ findings: [finding], config }));
    expect(evaluation.violations.map((violation) => violation.rule)).toContain('licenses.denied');
  });

  it('enforces an unknown-license policy of fail', () => {
    const config = resolveConfig({ licenses: { unknown: 'fail' } });
    const finding = makeFinding({
      category: 'license',
      severity: 'high',
      source: 'license/unknown',
      title: 'Unknown license',
    });
    const evaluation = evaluatePolicy(makeResult({ findings: [finding], config }));
    expect(evaluation.violations.map((violation) => violation.rule)).toContain('licenses.unknown');
  });

  it('enforces denied packages against the real graph', () => {
    const config = resolveConfig({ packages: { denied: ['lodash'] } });
    const evaluation = evaluatePolicy(makeResult({ config }));
    expect(evaluation.violations.map((violation) => violation.rule)).toContain('packages.denied');
  });

  it('enforces deprecated-package policy', () => {
    const config = resolveConfig({ security: { deprecated: { fail: true } } });
    const finding = makeFinding({
      category: 'maintenance',
      severity: 'medium',
      title: 'Deprecated package: request',
      source: 'registry/health',
    });
    const evaluation = evaluatePolicy(makeResult({ findings: [finding], config }));
    expect(evaluation.violations.map((violation) => violation.rule)).toContain('security.deprecated.fail');
  });

  it('evaluates only the findings it is given', () => {
    const config = resolveConfig({ security: { failOn: ['critical'] } });
    const result = makeResult({ findings: [highFinding], config });
    expect(evaluatePolicy(result, { findings: [] }).passed).toBe(true);
  });
});

describe('formatViolations', () => {
  it('renders a stable summary', () => {
    expect(formatViolations({ violations: [] } as never)).toBe('No policy violations.');
  });
});
