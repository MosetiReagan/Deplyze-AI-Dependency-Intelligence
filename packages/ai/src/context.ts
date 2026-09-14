import type { Finding, ProjectModel } from '@deplyze/core';
import type { ScanResult } from '@deplyze/scanners';

export interface ContextOptions {
  maxFindings?: number;
  /** Include dependency paths in the serialized finding (bounded). */
  maxPaths?: number;
}

export interface MinimizedContext {
  project: { name: string; manager: string; workspaces: number };
  stats: ScanResult['stats'];
  risk: { overall: number; band: string; categories: Array<{ category: string; score: number }> };
  findings: Array<Record<string, unknown>>;
  /** Note appended to the prompt documenting exactly what was sent. */
  disclosure: string;
}

/**
 * Build the minimal context sent to an AI provider.
 *
 * Only structured metadata is included: package names, versions, advisory
 * identifiers, severity and short evidence strings. Source code, file contents,
 * environment variables and full dependency trees are never transmitted. The
 * prompt records exactly which fields were sent so the behaviour is auditable.
 */
export function minimizeContext(
  result: ScanResult,
  findings: Finding[],
  options: ContextOptions = {},
): MinimizedContext {
  const maxFindings = options.maxFindings ?? result.config.ai.maxFindings;
  const maxPaths = options.maxPaths ?? 2;

  const selected = [...findings].sort((a, b) => rank(b.severity) - rank(a.severity)).slice(0, maxFindings);

  return {
    project: {
      name: result.project.name,
      manager: result.project.manager,
      workspaces: result.project.workspaces.length,
    },
    stats: result.stats,
    risk: {
      overall: result.risk.overall,
      band: result.risk.band,
      categories: result.risk.categories.map((category) => ({
        category: category.category,
        score: category.score,
      })),
    },
    findings: selected.map((finding) => ({
      id: finding.id,
      category: finding.category,
      severity: finding.severity,
      confidence: finding.confidence,
      title: finding.title,
      package: finding.package,
      version: finding.version,
      advisoryId: finding.advisoryId,
      evidence: finding.evidence.slice(0, 6).map((entry) => `${entry.kind}: ${entry.message}`),
      remediation: finding.remediation?.summary,
      paths: (finding.paths ?? []).slice(0, maxPaths).map((path) => path.join(' > ')),
    })),
    disclosure:
      `This request contains ${selected.length} finding(s${maxFindings < findings.length ? `, truncated from ${findings.length}` : ''}) ` +
      'and no source code. Only package names, versions, identifiers, severities and short evidence strings were sent.',
  };
}

/** Package metadata context for `deplyze package` / `deplyze guard` reviews. */
export function minimizeFinding(result: ScanResult, finding: Finding): Record<string, unknown> {
  return {
    project: result.project.name,
    risk: result.risk.overall,
    finding: {
      id: finding.id,
      category: finding.category,
      severity: finding.severity,
      title: finding.title,
      description: finding.description,
      package: finding.package,
      version: finding.version,
      evidence: finding.evidence.slice(0, 8).map((entry) => `${entry.kind}: ${entry.message}`),
    },
  };
}

function rank(severity: string): number {
  return { critical: 5, high: 4, medium: 3, low: 2, info: 1 }[severity] ?? 0;
}

export interface SystemPrompts {
  explain: string;
  remediate: string;
  upgradePlan: string;
  review: string;
}

export const BASE_SYSTEM_PROMPT =
  'You are a dependency-risk analyst embedded in Deplyze, an offline-first dependency intelligence tool. ' +
  'You are given the output of deterministic analysis. Never invent vulnerabilities, packages, versions, CVE identifiers or scores. ' +
  'If the data does not support a conclusion, say so explicitly. Distinguish clearly between what the evidence shows and what you are inferring. ' +
  'Be concise and concrete. Do not repeat the input back verbatim.';

export function systemPromptFor(task: keyof SystemPrompts, untrustedInstruction: string): string {
  const instructions: SystemPrompts = {
    explain:
      'Explain the finding to a developer: what was detected, why it matters, how confident Deplyze is, and the single most important next action. ' +
      'Use at most 180 words and no headings.',
    remediate:
      'Produce an ordered remediation plan. Group findings that share a root cause. Prefer upgrading over replacing, and state the compatibility risk of each step.',
    upgradePlan:
      'Produce an upgrade plan ordered by risk-adjusted value: security fixes first, then cheap compatible upgrades, then major upgrades that need review. ' +
      'For every major upgrade, list the specific checks a developer must perform. Never claim a major upgrade is safe.',
    review:
      'Review the dependency risk posture of this project. Highlight the two or three issues worth acting on now, and explicitly list what you cannot determine from the data provided.',
  };
  return `${BASE_SYSTEM_PROMPT}\n\n${untrustedInstruction}\n\n${instructions[task]}`;
}

export function projectSummaryLine(result: ScanResult, project?: ProjectModel): string {
  const model = project ?? result.project;
  return `Project ${model.name} (${model.manager}), ${result.stats.totalNodes - 1} packages, overall health ${result.risk.overall}/100.`;
}
