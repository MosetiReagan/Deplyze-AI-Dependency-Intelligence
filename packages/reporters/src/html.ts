import { categoryLabel, type Finding } from '@deplyze/core';
import { packageCount, type ScanResult } from '@deplyze/scanners';
import type { Reporter } from './types.js';

function escapeHtml(value: string): string {
  return value
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

const STYLES = `
:root{color-scheme:light dark;--bg:#ffffff;--fg:#111418;--muted:#5b6470;--card:#f6f8fa;--border:#d8dee4;
--critical:#a40e26;--high:#d1242f;--medium:#9a6700;--low:#0969da;--info:#57606a;--good:#1a7f37}
@media (prefers-color-scheme:dark){:root{--bg:#0d1117;--fg:#e6edf3;--muted:#9198a1;--card:#161b22;--border:#30363d;
--critical:#ff7b72;--high:#f85149;--medium:#d29922;--low:#58a6ff;--info:#8b949e;--good:#3fb950}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.55 ui-sans-serif,-apple-system,"Segoe UI",Roboto,sans-serif}
main{max-width:1000px;margin:0 auto;padding:32px 20px 80px}
h1{font-size:26px;margin:0 0 4px}
h2{font-size:18px;margin:36px 0 12px;padding-bottom:6px;border-bottom:1px solid var(--border)}
h3{font-size:15px;margin:22px 0 8px}
.sub{color:var(--muted);margin:0 0 24px}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px}
.card{background:var(--card);border:1px solid var(--border);border-radius:8px;padding:12px 14px}
.card .label{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.04em}
.card .value{font-size:22px;font-weight:600;margin-top:4px}
table{width:100%;border-collapse:collapse;font-size:14px}
th,td{text-align:left;padding:8px 10px;border-bottom:1px solid var(--border);vertical-align:top}
th{color:var(--muted);font-weight:600;font-size:12px;text-transform:uppercase;letter-spacing:.04em}
code{background:var(--card);border:1px solid var(--border);border-radius:4px;padding:1px 5px;font-size:12.5px}
.sev{font-weight:700;text-transform:uppercase;font-size:11px;letter-spacing:.05em}
.sev-critical{color:var(--critical)}.sev-high{color:var(--high)}.sev-medium{color:var(--medium)}
.sev-low{color:var(--low)}.sev-info{color:var(--info)}
details{border:1px solid var(--border);border-radius:8px;padding:10px 14px;margin:8px 0;background:var(--card)}
summary{cursor:pointer;font-weight:600}
.bar{height:8px;border-radius:4px;background:var(--border);overflow:hidden;margin-top:6px}
.bar>span{display:block;height:100%;background:var(--good)}
.evidence{margin:8px 0 0;padding-left:18px;color:var(--muted)}
footer{margin-top:40px;color:var(--muted);font-size:13px}
`;

function scoreBar(score: number): string {
  return `<div class="bar"><span style="width:${Math.max(0, Math.min(100, score))}%"></span></div>`;
}

function findingDetails(finding: Finding): string {
  const evidence = finding.evidence
    .map((entry) => `<li><code>${escapeHtml(entry.kind)}</code> ${escapeHtml(entry.message)}</li>`)
    .join('');
  const steps = (finding.remediation?.steps ?? []).map((step) => `<li>${escapeHtml(step)}</li>`).join('');
  const refs = (finding.references ?? [])
    .slice(0, 8)
    .map((ref) => `<li><a href="${escapeHtml(ref)}" rel="noreferrer noopener">${escapeHtml(ref)}</a></li>`)
    .join('');
  return `<details>
<summary><span class="sev sev-${finding.severity}">${finding.severity}</span> ${escapeHtml(finding.title)}</summary>
<p>${escapeHtml(finding.description)}</p>
<p><strong>ID</strong> <code>${escapeHtml(finding.id)}</code> · <strong>Confidence</strong> ${finding.confidence}${
    finding.package
      ? ` · <strong>Package</strong> <code>${escapeHtml(finding.package)}@${escapeHtml(finding.version ?? '')}</code>`
      : ''
  }</p>
${evidence ? `<strong>Evidence</strong><ul class="evidence">${evidence}</ul>` : ''}
${finding.remediation ? `<p><strong>Recommended action:</strong> ${escapeHtml(finding.remediation.summary)}</p>` : ''}
${finding.remediation?.command ? `<p><code>${escapeHtml(finding.remediation.command)}</code></p>` : ''}
${steps ? `<strong>Steps</strong><ul class="evidence">${steps}</ul>` : ''}
${refs ? `<strong>References</strong><ul class="evidence">${refs}</ul>` : ''}
</details>`;
}

export function renderHtml(result: ScanResult): string {
  const stats = result.stats;
  const categories = result.risk.categories
    .map(
      (
        category,
      ) => `<div class="card"><div class="label">${escapeHtml(categoryLabel(category.category))}</div>
<div class="value">${category.score}/100</div>${scoreBar(category.score)}</div>`,
    )
    .join('');

  const contributors = result.risk.contributors
    .map(
      (contributor) =>
        `<tr><td>+${contributor.points}</td><td>${escapeHtml(categoryLabel(contributor.category))}</td><td>${escapeHtml(contributor.reason)}</td></tr>`,
    )
    .join('');

  const byCategory = new Map<string, Finding[]>();
  for (const finding of result.findings) {
    const list = byCategory.get(finding.category) ?? [];
    list.push(finding);
    byCategory.set(finding.category, list);
  }
  const sections = [...byCategory.entries()]
    .sort((a, b) => b[1].length - a[1].length)
    .map(
      ([category, findings]) =>
        `<h3>${escapeHtml(categoryLabel(category as Finding['category']))} (${findings.length})</h3>` +
        findings.map(findingDetails).join(''),
    )
    .join('');

  const warnings = result.project.warnings.length
    ? `<h2>Analysis warnings</h2><ul>${result.project.warnings
        .map((warning) => `<li>${escapeHtml(warning.message)}</li>`)
        .join('')}</ul>`
    : '';

  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="generator" content="Deplyze 0.1.0">
<title>Deplyze report — ${escapeHtml(result.project.name)}</title>
<style>${STYLES}</style>
</head>
<body>
<main>
<h1>Deplyze — AI Dependency Intelligence</h1>
<p class="sub">${escapeHtml(result.project.name)}${result.project.version ? `@${escapeHtml(result.project.version)}` : ''} · ${escapeHtml(result.project.manager)} · generated ${escapeHtml(result.finishedAt)}</p>

<div class="grid">
  <div class="card"><div class="label">Overall health</div><div class="value">${result.risk.overall}/100</div>${scoreBar(result.risk.overall)}</div>
  <div class="card"><div class="label">Resolved packages</div><div class="value">${packageCount(result)}</div></div>
  <div class="card"><div class="label">Direct</div><div class="value">${stats.directNodes}</div></div>
  <div class="card"><div class="label">Transitive</div><div class="value">${stats.transitiveNodes}</div></div>
  <div class="card"><div class="label">Critical</div><div class="value">${result.summary.critical}</div></div>
  <div class="card"><div class="label">High</div><div class="value">${result.summary.high}</div></div>
</div>

<h2>Health by category</h2>
<div class="grid">${categories}</div>

<h2>Score contributors</h2>
${contributors ? `<table><thead><tr><th>Impact</th><th>Category</th><th>Reason</th></tr></thead><tbody>${contributors}</tbody></table>` : '<p>No risk contributors.</p>'}
<p class="sub">${escapeHtml(result.risk.methodology)}</p>

<h2>Findings (${result.summary.total})</h2>
${sections || '<p>No findings were reported.</p>'}

<h2>Dependency graph</h2>
<table>
<thead><tr><th>Metric</th><th>Value</th></tr></thead>
<tbody>
<tr><td>Graph edges</td><td>${stats.edgeCount}</td></tr>
<tr><td>Maximum depth</td><td>${stats.maxDepth}</td></tr>
<tr><td>Average depth</td><td>${stats.averageDepth}</td></tr>
<tr><td>Duplicate-version packages</td><td>${stats.duplicateVersions}</td></tr>
<tr><td>Workspaces</td><td>${result.project.workspaces.length}</td></tr>
</tbody>
</table>

${warnings}

<footer>
<p>Deplyze reports only what it can evidence. Absence of a finding is not proof of safety. Analysis duration ${result.diagnostics.durationMs} ms · ${result.diagnostics.sourceFilesScanned} source files scanned.</p>
</footer>
</main>
</body>
</html>
`;
}

export const htmlReporter: Reporter = {
  id: 'html',
  contentType: 'text/html',
  extension: 'html',
  render: renderHtml,
};
