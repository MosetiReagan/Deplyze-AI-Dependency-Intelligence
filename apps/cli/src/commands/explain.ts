import { DeplyzeError, ErrorCode, categoryLabel } from '@deplyze/core';
import { AiRunner, assertAiEnabled } from '@deplyze/ai';
import { runScanCommand, type ScanFlags } from './shared.js';
import { printHeading } from '../output.js';

export interface ExplainFlags extends ScanFlags {
  ai?: boolean;
}

export async function explainCommand(findingId: string, flags: ExplainFlags): Promise<number> {
  const { context, result } = await runScanCommand(flags);
  const needle = findingId.trim().toUpperCase();
  const finding =
    result.findings.find((entry) => entry.id.toUpperCase() === needle) ??
    result.findings.find((entry) => entry.advisoryId?.toUpperCase() === needle) ??
    result.findings.find((entry) => entry.id.toUpperCase().startsWith(needle));

  if (!finding) {
    throw new DeplyzeError(ErrorCode.DEPLYZE_E_USAGE, `No finding matched "${findingId}".`, {
      hint: 'Run `deplyze scan` and copy a finding id (for example DEP-1A2B3C4D5E), or use an advisory id such as GHSA-xxxx-xxxx-xxxx.',
    });
  }

  const lines: string[] = [];
  lines.push(`${finding.title}`);
  lines.push('');
  lines.push(`  id          ${finding.id}`);
  lines.push(`  category    ${categoryLabel(finding.category)}`);
  lines.push(`  severity    ${finding.severity}`);
  lines.push(`  confidence  ${finding.confidence}`);
  lines.push(`  detector    ${finding.source}`);
  if (finding.package)
    lines.push(`  package     ${finding.package}${finding.version ? `@${finding.version}` : ''}`);
  if (finding.advisoryId) lines.push(`  advisory    ${finding.advisoryId}`);
  lines.push('');
  lines.push('What was found');
  lines.push(`  ${finding.description}`);
  lines.push('');

  if (finding.paths && finding.paths.length > 0) {
    lines.push('How it entered the project');
    for (const path of finding.paths.slice(0, 5)) {
      lines.push(
        `  ${path.map((id) => (id.startsWith('root:') ? `${id.slice(5) === '.' ? '(project)' : id.slice(5)}` : id.slice(id.indexOf(':') + 1))).join(' > ')}`,
      );
    }
    lines.push('');
  }

  lines.push('Evidence');
  for (const evidence of finding.evidence) {
    lines.push(`  [${evidence.kind}] ${evidence.message}`);
  }
  lines.push('');

  if (finding.remediation) {
    lines.push('Recommended action');
    lines.push(`  ${finding.remediation.summary}`);
    if (finding.remediation.command) lines.push(`  $ ${finding.remediation.command}`);
    for (const step of finding.remediation.steps ?? []) lines.push(`  - ${step}`);
    lines.push('');
  }

  if (finding.references && finding.references.length > 0) {
    lines.push('References');
    for (const reference of finding.references.slice(0, 8)) lines.push(`  ${reference}`);
    lines.push('');
  }

  const wantsAi = flags.ai === true;

  if (flags.format === 'json' || flags.json) {
    const payload: Record<string, unknown> = { finding };
    if (wantsAi) {
      assertAiEnabled(context.config);
      const runner = new AiRunner({ config: context.config, logger: context.logger });
      const ai = await runner.explain(result, finding);
      payload.ai = { ...ai, generatedBy: 'ai' };
    }
    process.stdout.write(`${JSON.stringify(payload, null, 2)}\n`);
    return 0;
  }

  printHeading(`Deplyze explain — ${finding.id}`);
  process.stdout.write(lines.join('\n'));

  if (wantsAi) {
    assertAiEnabled(context.config);
    const runner = new AiRunner({ config: context.config, logger: context.logger });
    const ai = await runner.explain(result, finding);
    process.stdout.write(
      '\nAI-generated analysis (provider: ' + ai.provider + ', model: ' + ai.model + ')\n',
    );
    process.stdout.write('─'.repeat(72) + '\n');
    process.stdout.write(`${ai.text}\n`);
    process.stdout.write(`\n(${ai.disclosure})\n`);
    process.stdout.write(
      'This text is AI-generated and may be incomplete or wrong. The evidence above is authoritative.\n',
    );
  } else {
    process.stdout.write(
      '\nTip: add --ai to request an AI-authored explanation (requires ai.enabled in .deplyze.yml).\n',
    );
  }
  return 0;
}
