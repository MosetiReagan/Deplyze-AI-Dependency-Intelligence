import { categoryLabel, type Finding } from '@deplyze/core';
import { packageCount, type ScanResult } from '@deplyze/scanners';
import type { Reporter } from './types.js';

function escapeCell(value: string): string {
  return value.replace(/\|/g, '\\|').replace(/\n+/g, ' ');
}

function findingSection(finding: Finding): string[] {
  const lines: string[] = [];
  const location = finding.package
    ? `\`${finding.package}${finding.version ? `@${finding.version}` : ''}\``
    : '';
  lines.push(`#### ${finding.title}`);
  lines.push('');
  lines.push(`- **ID**: \`${finding.id}\``);
  lines.push(`- **Severity**: ${finding.severity} · **Confidence**: ${finding.confidence}`);
  lines.push(`- **Category**: ${categoryLabel(finding.category)}`);
  if (location) lines.push(`- **Package**: ${location}`);
  if (finding.advisoryId) lines.push(`- **Advisory**: \`${finding.advisoryId}\``);
  lines.push('');
  lines.push(finding.description);
  lines.push('');
  if (finding.evidence.length > 0) {
    lines.push('**Evidence**');
    lines.push('');
    for (const evidence of finding.evidence) {
      lines.push(`- \`${evidence.kind}\` — ${evidence.message}`);
    }
    lines.push('');
  }
  if (finding.remediation) {
    lines.push('**Remediation**');
    lines.push('');
    lines.push(finding.remediation.summary);
    lines.push('');
    if (finding.remediation.command) {
      lines.push('```bash');
      lines.push(finding.remediation.command);
      lines.push('```');
      lines.push('');
    }
    for (const step of finding.remediation.steps ?? []) lines.push(`- ${step}`);
    if ((finding.remediation.steps ?? []).length > 0) lines.push('');
  }
  if (finding.references && finding.references.length > 0) {
    lines.push('**References**');
    lines.push('');
    for (const reference of finding.references.slice(0, 10)) lines.push(`- ${reference}`);
    lines.push('');
  }
  return lines;
}

export function renderMarkdown(result: ScanResult): string {
  const lines: string[] = [];
  const stats = result.stats;

  lines.push(`# Deplyze report — ${result.project.name}`);
  lines.push('');
  lines.push(`> Generated ${result.finishedAt} by Deplyze (AI Dependency Intelligence).`);
  lines.push('');
  lines.push('## Executive summary');
  lines.push('');
  lines.push(
    `Deplyze analysed ${packageCount(result)} resolved packages ` +
      `(${stats.directNodes} direct, ${stats.transitiveNodes} transitive) across ${result.project.workspaces.length} workspace(s) ` +
      `using the ${result.project.manager} lockfile.`,
  );
  lines.push('');
  lines.push(`**Overall dependency health: ${result.risk.overall}/100 (${result.risk.band}).**`);
  lines.push('');
  lines.push('| Finding severity | Count |');
  lines.push('| --- | --- |');
  lines.push(`| Critical | ${result.summary.critical} |`);
  lines.push(`| High | ${result.summary.high} |`);
  lines.push(`| Medium | ${result.summary.medium} |`);
  lines.push(`| Low | ${result.summary.low} |`);
  lines.push(`| Info | ${result.summary.info} |`);
  lines.push(`| **Total** | **${result.summary.total}** |`);
  lines.push('');

  lines.push('## Health scores');
  lines.push('');
  lines.push('| Category | Score |');
  lines.push('| --- | --- |');
  for (const category of result.risk.categories) {
    lines.push(`| ${categoryLabel(category.category)} | ${category.score}/100 |`);
  }
  lines.push('');

  if (result.risk.contributors.length > 0) {
    lines.push('### Score contributors');
    lines.push('');
    for (const contributor of result.risk.contributors) {
      lines.push(
        `- **+${contributor.points}** (${categoryLabel(contributor.category)}) — ${contributor.reason}`,
      );
    }
    lines.push('');
    lines.push(`_${result.risk.methodology}_`);
    lines.push('');
  }

  const byCategory = new Map<string, Finding[]>();
  for (const finding of result.findings) {
    const list = byCategory.get(finding.category) ?? [];
    list.push(finding);
    byCategory.set(finding.category, list);
  }

  lines.push('## Findings');
  lines.push('');
  if (result.findings.length === 0) {
    lines.push('No findings were reported.');
    lines.push('');
  }
  for (const [category, findings] of [...byCategory.entries()].sort((a, b) => b[1].length - a[1].length)) {
    lines.push(`### ${categoryLabel(category as Finding['category'])} (${findings.length})`);
    lines.push('');
    lines.push('| Severity | Package | Finding | ID |');
    lines.push('| --- | --- | --- | --- |');
    for (const finding of findings) {
      lines.push(
        `| ${finding.severity} | ${escapeCell(finding.package ? `${finding.package}${finding.version ? `@${finding.version}` : ''}` : '—')} | ${escapeCell(finding.title)} | \`${finding.id}\` |`,
      );
    }
    lines.push('');
  }

  const detail = result.findings.filter((finding) => finding.severity !== 'info');
  if (detail.length > 0) {
    lines.push('## Finding details');
    lines.push('');
    for (const finding of detail) {
      lines.push(...findingSection(finding));
    }
  }

  lines.push('## Dependency graph statistics');
  lines.push('');
  lines.push('| Metric | Value |');
  lines.push('| --- | --- |');
  lines.push(`| Resolved packages | ${packageCount(result)} |`);
  lines.push(`| Direct dependencies | ${stats.directNodes} |`);
  lines.push(`| Transitive dependencies | ${stats.transitiveNodes} |`);
  lines.push(`| Graph edges | ${stats.edgeCount} |`);
  lines.push(`| Max depth | ${stats.maxDepth} |`);
  lines.push(`| Average depth | ${stats.averageDepth} |`);
  lines.push(`| Packages with duplicate versions | ${stats.duplicateVersions} |`);
  lines.push('');

  if (result.project.warnings.length > 0) {
    lines.push('## Analysis warnings');
    lines.push('');
    for (const warning of result.project.warnings) lines.push(`- ${warning.message}`);
    lines.push('');
  }

  lines.push('## Diagnostics');
  lines.push('');
  lines.push(`- Analysis duration: ${result.diagnostics.durationMs} ms`);
  lines.push(`- Source files scanned: ${result.diagnostics.sourceFilesScanned}`);
  lines.push(`- Registry packages resolved: ${result.diagnostics.registryPackagesResolved}`);
  lines.push(`- Network used: ${result.diagnostics.usedNetwork ? 'yes' : 'no (offline or cached)'}`);
  if (result.diagnostics.unresolvedAdvisories.length > 0) {
    lines.push(
      `- Advisories that could not be retrieved: ${result.diagnostics.unresolvedAdvisories.join(', ')}`,
    );
  }
  lines.push('');
  lines.push('---');
  lines.push('');
  lines.push('_Deplyze reports evidence it can verify. Absence of a finding is not proof of safety._');

  return `${lines.join('\n')}\n`;
}

export const markdownReporter: Reporter = {
  id: 'markdown',
  contentType: 'text/markdown',
  extension: 'md',
  render: renderMarkdown,
};
