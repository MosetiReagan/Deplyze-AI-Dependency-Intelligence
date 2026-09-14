import { categoryLabel, type Finding } from '@deplyze/core';
import { packageCount, type ScanResult } from '@deplyze/scanners';
import { createPalette, scoreColor, severityColor, type Palette } from './color.js';
import type { ReportOptions, Reporter } from './types.js';

const CATEGORY_WIDTH = 16;

function formatScore(palette: Palette, label: string, score: number): string {
  const padded = label.padEnd(CATEGORY_WIDTH, ' ');
  return `  ${palette.dim(padded)}${scoreColor(palette, score)(`${score.toFixed(0).padStart(3)}/100`)}`;
}

function findingLine(palette: Palette, finding: Finding, projectRoot: string): string[] {
  const color = severityColor(palette, finding.severity);
  const location = finding.package ? `${finding.package}${finding.version ? `@${finding.version}` : ''}` : '';
  const lines = [
    `  ${color(finding.severity.toUpperCase().padEnd(8))} ${palette.dim(`[${categoryLabel(finding.category)}]`)} ${finding.title}`,
  ];
  if (location) lines.push(`           ${palette.dim(location)}  ${palette.gray(finding.id)}`);
  else lines.push(`           ${palette.gray(finding.id)}`);
  if (finding.paths && finding.paths.length > 0) {
    const first = finding.paths[0] as string[];
    lines.push(`           ${palette.dim('path:')} ${palette.gray(describePath(first, projectRoot))}`);
  }
  return lines;
}

function describePath(ids: string[], projectRoot: string): string {
  void projectRoot;
  return ids
    .map((id) => {
      if (id.startsWith('root:'))
        return id.slice('root:'.length) === '.' ? '(root)' : id.slice('root:'.length);
      const colon = id.indexOf(':');
      return id.slice(colon + 1);
    })
    .join(' > ');
}

export function renderTerminal(result: ScanResult, options: ReportOptions = {}): string {
  const palette = createPalette(options.color ?? 'auto');
  const out: string[] = [];
  const maxFindings = options.maxFindings ?? 12;

  out.push(palette.bold('Deplyze — AI Dependency Intelligence'));
  out.push('');
  out.push(
    `  ${palette.dim('Project:')}     ${result.project.name}${result.project.version ? `@${result.project.version}` : ''}`,
  );
  out.push(`  ${palette.dim('Ecosystem:')}   ${result.project.manager}`);
  out.push(`  ${palette.dim('Workspaces:')}  ${result.project.workspaces.length}`);
  out.push(
    `  ${palette.dim('Resolved:')}    ${packageCount(result)} packages ` +
      `(direct ${result.stats.directNodes}, transitive ${packageCount(result) - result.stats.directNodes})`,
  );
  if (result.project.lockfiles.length > 0) {
    const parsed = result.project.lockfiles.filter((lockfile) => lockfile.parsed);
    out.push(
      `  ${palette.dim('Lockfile:')}    ${
        parsed.length > 0
          ? `${parsed[0]?.path} (${parsed[0]?.manager}, ${parsed[0]?.resolvedPackages} packages)`
          : `${result.project.lockfiles[0]?.path} — not parsed`
      }`,
    );
  }
  out.push('');

  out.push(palette.bold('  Health'));
  for (const category of result.risk.categories) {
    out.push(formatScore(palette, categoryLabelRisk(category.category), category.score));
  }
  out.push(
    `  ${palette.dim('Overall'.padEnd(CATEGORY_WIDTH, ' '))}${scoreColor(
      palette,
      result.risk.overall,
    )(`${result.risk.overall.toFixed(0).padStart(3)}/100`)} ${palette.dim(`(${result.risk.band})`)}`,
  );
  out.push('');

  const summary = result.summary;
  out.push(palette.bold('  Findings'));
  if (summary.total === 0) {
    out.push(`  ${palette.green('No findings.')}`);
  } else {
    const counts: Array<[string, number]> = [
      ['Critical', summary.critical],
      ['High', summary.high],
      ['Medium', summary.medium],
      ['Low', summary.low],
      ['Info', summary.info],
    ];
    const rendered = counts
      .filter(([, count]) => count > 0)
      .map(([label, count]) => severityColor(palette, label.toLowerCase())(`${count} ${label}`))
      .join(palette.dim(' · '));
    out.push(`  ${rendered}${palette.dim(`  (${summary.total} total)`)}`);
  }
  out.push('');

  const relevant = result.findings.filter(
    (finding) => options.includeInfo !== false || finding.severity !== 'info',
  );
  const visible = relevant.slice(0, maxFindings);
  if (visible.length > 0) {
    out.push(palette.bold('  Top findings'));
    for (const finding of visible) {
      out.push(...findingLine(palette, finding, result.project.root));
    }
    if (relevant.length > visible.length) {
      out.push(
        `  ${palette.dim(`… ${relevant.length - visible.length} more (see deplyze report --format markdown)`)}`,
      );
    }
    out.push('');
  }

  if (result.project.warnings.length > 0) {
    out.push(palette.bold('  Warnings'));
    for (const warning of result.project.warnings.slice(0, 5)) {
      out.push(`  ${palette.yellow('!')} ${warning.message}`);
    }
    out.push('');
  }

  if (result.diagnostics.unparsedLockfiles.length > 0) {
    out.push(palette.bold('  Lockfile warnings'));
    for (const entry of result.diagnostics.unparsedLockfiles) {
      out.push(`  ${palette.yellow('!')} ${entry.path}: ${entry.reason}`);
    }
    out.push('');
  }

  out.push(palette.bold('  Next'));
  out.push(`  ${palette.dim('deplyze scan --format json        machine-readable results')}`);
  out.push(`  ${palette.dim('deplyze security                  vulnerabilities in detail')}`);
  out.push(`  ${palette.dim('deplyze outdated                  version drift')}`);
  out.push(`  ${palette.dim('deplyze upgrade-plan              ordered remediation plan')}`);
  out.push(`  ${palette.dim('deplyze report --format markdown  shareable report')}`);

  return out.join('\n');
}

function categoryLabelRisk(category: string): string {
  switch (category) {
    case 'supply-chain':
      return 'Supply Chain';
    case 'dependency-health':
      return 'Dep. Health';
    case 'upgrade-risk':
      return 'Upgrade Risk';
    default:
      return category.charAt(0).toUpperCase() + category.slice(1);
  }
}

export const terminalReporter: Reporter = {
  id: 'terminal',
  contentType: 'text/plain',
  extension: 'txt',
  render: renderTerminal,
};
