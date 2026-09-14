import type { Confidence, Finding, FindingCategory, Severity } from './types.js';
import { shortHash } from './hash.js';
import { severityRank } from './severity.js';

export interface FindingInput {
  category: FindingCategory;
  severity: Severity;
  confidence: Confidence;
  title: string;
  description: string;
  source: string;
  package?: string;
  version?: string;
  ecosystem?: string;
  evidence?: Finding['evidence'];
  remediation?: Finding['remediation'];
  references?: string[];
  advisoryId?: string;
  weight?: number;
  paths?: string[][];
  /** Extra discriminator when several findings share package/rule/title. */
  discriminator?: string;
  /** Stable, human-meaningful id (e.g. an advisory or rule id). */
  stableId?: string;
}

/**
 * Build a Finding with a deterministic id.
 *
 * Ids are derived from the stable identity of the issue (rule + package +
 * version + advisory), never from array position, so suppressions keep working
 * across runs and lockfile churn.
 */
export function createFinding(input: FindingInput): Finding {
  const identity =
    input.stableId ??
    `${input.source}|${input.category}|${input.package ?? ''}|${input.version ?? ''}|${
      input.advisoryId ?? ''
    }|${input.title}|${input.discriminator ?? ''}`;
  const finding: Finding = {
    id: `DEP-${shortHash(identity, 10).toUpperCase()}`,
    category: input.category,
    severity: input.severity,
    confidence: input.confidence,
    title: input.title,
    description: input.description,
    source: input.source,
    evidence: input.evidence ?? [],
  };
  if (input.package !== undefined) finding.package = input.package;
  if (input.version !== undefined) finding.version = input.version;
  if (input.ecosystem !== undefined) finding.ecosystem = input.ecosystem as Finding['ecosystem'];
  if (input.remediation !== undefined) finding.remediation = input.remediation;
  if (input.references !== undefined) finding.references = input.references;
  if (input.advisoryId !== undefined) finding.advisoryId = input.advisoryId;
  if (input.weight !== undefined) finding.weight = input.weight;
  if (input.paths !== undefined) finding.paths = input.paths;
  return finding;
}

/** Deduplicate findings that share an id, merging evidence. */
export function dedupeFindings(findings: Finding[]): Finding[] {
  const byId = new Map<string, Finding>();
  for (const finding of findings) {
    const existing = byId.get(finding.id);
    if (!existing) {
      byId.set(finding.id, finding);
      continue;
    }
    const seen = new Set(existing.evidence.map((e) => `${e.kind}:${e.message}`));
    for (const evidence of finding.evidence) {
      if (!seen.has(`${evidence.kind}:${evidence.message}`)) {
        existing.evidence.push(evidence);
        seen.add(`${evidence.kind}:${evidence.message}`);
      }
    }
    if (
      finding.severity !== existing.severity &&
      severityRank(finding.severity) > severityRank(existing.severity)
    ) {
      existing.severity = finding.severity;
    }
    if (finding.paths) {
      existing.paths = [...(existing.paths ?? []), ...finding.paths];
    }
  }
  return [...byId.values()];
}

export function sortFindings(findings: Finding[]): Finding[] {
  return [...findings].sort((a, b) => {
    const bySeverity = severityRank(b.severity) - severityRank(a.severity);
    if (bySeverity !== 0) return bySeverity;
    const pkg = (a.package ?? '').localeCompare(b.package ?? '');
    if (pkg !== 0) return pkg;
    return a.title.localeCompare(b.title);
  });
}
