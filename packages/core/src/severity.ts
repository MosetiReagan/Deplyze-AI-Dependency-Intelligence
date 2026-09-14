import type { Confidence, Severity, FindingCategory, Finding, ScanSummaryCounts } from './types.js';
import { SEVERITIES } from './types.js';

const RANK: Record<Severity, number> = {
  critical: 5,
  high: 4,
  medium: 3,
  low: 2,
  info: 1,
  unknown: 0,
};

export function severityRank(severity: Severity): number {
  return RANK[severity] ?? 0;
}

export function compareSeverity(a: Severity, b: Severity): number {
  return severityRank(b) - severityRank(a);
}

export function isSeverity(value: unknown): value is Severity {
  return typeof value === 'string' && (SEVERITIES as readonly string[]).includes(value);
}

/** Severities at or above `threshold`, ordered most severe first. */
export function severitiesAtOrAbove(threshold: Severity): Severity[] {
  return SEVERITIES.filter((s) => severityRank(s) >= severityRank(threshold) && s !== 'unknown');
}

const CONFIDENCE_RANK: Record<Confidence, number> = {
  high: 3,
  medium: 2,
  low: 1,
  unknown: 0,
};

export function compareConfidence(a: Confidence, b: Confidence): number {
  return CONFIDENCE_RANK[b] - CONFIDENCE_RANK[a];
}

export function summarize(findings: Finding[]): ScanSummaryCounts {
  const counts: ScanSummaryCounts = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
    unknown: 0,
    total: findings.length,
    byCategory: {},
  };
  for (const finding of findings) {
    counts[finding.severity] += 1;
    counts.byCategory[finding.category] = (counts.byCategory[finding.category] ?? 0) + 1;
  }
  return counts;
}

/** Human-readable label for a finding or risk category. */
export function categoryLabel(category: FindingCategory | string): string {
  switch (category) {
    case 'supply-chain':
      return 'Supply Chain';
    default:
      return category.charAt(0).toUpperCase() + category.slice(1);
  }
}
