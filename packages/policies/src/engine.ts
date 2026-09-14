import { EXIT, severityRank, type Finding, type Severity } from '@deplyze/core';
import type { ResolvedConfig } from '@deplyze/config';
import type { ScanResult } from '@deplyze/scanners';
import { applySuppressions, type SuppressionMatch, type SuppressionOutcome } from './suppressions.js';

export interface PolicyViolation {
  /** Stable rule id, e.g. `security.failOn`, `licenses.denied`. */
  rule: string;
  message: string;
  /** Severity that triggered the rule, when applicable. */
  severity?: Severity;
  findingIds: string[];
}

export interface PolicyEvaluation {
  violations: PolicyViolation[];
  /** Findings that remain after suppressions. */
  active: Finding[];
  suppressed: SuppressionMatch[];
  expiredSuppressions: ResolvedConfig['ignore'];
  unusedSuppressions: ResolvedConfig['ignore'];
  exitCode: 0 | 1;
  passed: boolean;
}

export interface PolicyOptions {
  /** Findings to evaluate. Defaults to every finding in the result. */
  findings?: Finding[];
  now?: Date;
}

export function evaluatePolicy(result: ScanResult, options: PolicyOptions = {}): PolicyEvaluation {
  const config = result.config;
  const findings = options.findings ?? result.findings;
  const outcome: SuppressionOutcome = applySuppressions(findings, config, options.now ?? new Date());

  const violations: PolicyViolation[] = [];
  const failOn = config.ci.failOn.length > 0 ? config.ci.failOn : config.security.failOn;
  const failOnRanks = failOn.map((severity) => severityRank(severity));

  // 1. Severity threshold across all categories.
  const thresholdFindings = outcome.active.filter((finding) =>
    failOnRanks.some((rank) => severityRank(finding.severity) >= rank),
  );
  for (const finding of thresholdFindings) {
    violations.push({
      rule: `security.failOn:${finding.severity}`,
      message: `${finding.severity} finding is at or above the configured failure threshold: ${finding.title}`,
      severity: finding.severity,
      findingIds: [finding.id],
    });
  }

  // 2. Vulnerability count ceilings.
  const vulnerabilities = outcome.active.filter((finding) => finding.category === 'vulnerability');
  const ceilings: Array<[keyof typeof config.security.vulnerabilities, Severity, number | undefined]> = [
    ['maxCritical', 'critical', config.security.vulnerabilities.maxCritical],
    ['maxHigh', 'high', config.security.vulnerabilities.maxHigh],
    ['maxMedium', 'medium', config.security.vulnerabilities.maxMedium],
  ];
  for (const [rule, severity, ceiling] of ceilings) {
    if (ceiling === undefined) continue;
    const matching = vulnerabilities.filter((finding) => finding.severity === severity);
    if (matching.length > ceiling) {
      violations.push({
        rule: `security.vulnerabilities.${String(rule)}`,
        message: `${matching.length} ${severity} vulnerabilities exceed the configured maximum of ${ceiling}.`,
        severity,
        findingIds: matching.map((finding) => finding.id),
      });
    }
  }

  // 3. Deprecated dependencies.
  if (config.security.deprecated.fail) {
    const deprecated = outcome.active.filter(
      (finding) => finding.category === 'maintenance' && finding.title.toLowerCase().includes('deprecated'),
    );
    if (deprecated.length > 0) {
      violations.push({
        rule: 'security.deprecated.fail',
        message: `${deprecated.length} deprecated package(s) present and the policy requires none.`,
        findingIds: deprecated.map((finding) => finding.id),
      });
    }
  }

  // 4. Install scripts.
  if (config.security.installScripts.failOn.length > 0) {
    const ranks = config.security.installScripts.failOn.map((severity) => severityRank(severity));
    const scripts = outcome.active.filter(
      (finding) =>
        finding.source === 'supply-chain/lifecycle-scripts' &&
        ranks.some((rank) => severityRank(finding.severity) >= rank),
    );
    if (scripts.length > 0) {
      violations.push({
        rule: 'security.installScripts.failOn',
        message: `${scripts.length} package(s) with install scripts at or above the configured severity.`,
        findingIds: scripts.map((finding) => finding.id),
      });
    }
  }

  // 5. License policy.
  if (config.licenses.denied.length > 0 && config.licenses.failOnDenied) {
    const licenseViolations = outcome.active.filter(
      (finding) => finding.category === 'license' && finding.source === 'license/policy',
    );
    if (licenseViolations.length > 0) {
      violations.push({
        rule: 'licenses.denied',
        message: `${licenseViolations.length} package(s) use a denied license.`,
        severity: 'high',
        findingIds: licenseViolations.map((finding) => finding.id),
      });
    }
  }
  if (config.licenses.unknown === 'fail') {
    const unknown = outcome.active.filter((finding) => finding.source === 'license/unknown');
    if (unknown.length > 0) {
      violations.push({
        rule: 'licenses.unknown',
        message: `${unknown.length} package(s) have an unverifiable license and the policy requires a known license.`,
        findingIds: unknown.map((finding) => finding.id),
      });
    }
  }

  // 6. Denied packages.
  if (config.packages.denied.length > 0) {
    const denied = new Set(config.packages.denied);
    const offending = result.graph.nodes().filter((node) => node.depth > 0 && denied.has(node.name));
    if (offending.length > 0) {
      const names = [...new Set(offending.map((node) => node.name))];
      violations.push({
        rule: 'packages.denied',
        message: `Denied package(s) present in the dependency graph: ${names.join(', ')}.`,
        findingIds: offending.map((node) => `package:${node.id}`),
      });
    }
  }

  return {
    violations,
    active: outcome.active,
    suppressed: outcome.suppressed,
    expiredSuppressions: outcome.expired,
    unusedSuppressions: outcome.unused,
    exitCode: violations.length > 0 ? EXIT.POLICY_VIOLATION : EXIT.PASS,
    passed: violations.length === 0,
  };
}

/** Render policy violations as a stable, human-readable block. */
export function formatViolations(evaluation: PolicyEvaluation): string {
  if (evaluation.violations.length === 0) return 'No policy violations.';
  const lines = [`${evaluation.violations.length} policy violation(s):`];
  for (const violation of evaluation.violations) {
    lines.push(`  - [${violation.rule}] ${violation.message}`);
  }
  return lines.join('\n');
}
