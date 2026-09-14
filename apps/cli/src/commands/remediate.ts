import { AiRunner, assertAiEnabled } from '@deplyze/ai';
import { compareVersions, type Finding } from '@deplyze/core';
import { runScanCommand, type ScanFlags } from './shared.js';
import { printHeading } from '../output.js';

export interface PlanFlags extends ScanFlags {
  ai?: boolean;
}

interface PlanStep {
  order: number;
  package: string;
  from: string;
  to: string;
  breaking: boolean;
  reasons: string[];
  findingIds: string[];
}

export function buildUpgradePlan(findings: Finding[]): PlanStep[] {
  const steps = new Map<string, PlanStep>();
  for (const finding of findings) {
    for (const upgrade of finding.remediation?.upgrades ?? []) {
      const key = `${upgrade.package}|${upgrade.from}|${upgrade.to}`;
      const existing = steps.get(key);
      if (existing) {
        existing.reasons.push(finding.title);
        existing.findingIds.push(finding.id);
        continue;
      }
      steps.set(key, {
        order: 0,
        package: upgrade.package,
        from: upgrade.from,
        to: upgrade.to,
        breaking: upgrade.breaking,
        reasons: [finding.title],
        findingIds: [finding.id],
      });
    }
  }

  const securityFirst = new Set(
    findings.filter((finding) => finding.category === 'vulnerability').map((finding) => finding.id),
  );

  const ordered = [...steps.values()].sort((a, b) => {
    const aSecurity = a.findingIds.some((id) => securityFirst.has(id)) ? 0 : 1;
    const bSecurity = b.findingIds.some((id) => securityFirst.has(id)) ? 0 : 1;
    if (aSecurity !== bSecurity) return aSecurity - bSecurity;
    if (a.breaking !== b.breaking) return a.breaking ? 1 : -1;
    return compareVersions(a.from, b.from);
  });
  return ordered.map((step, index) => ({ ...step, order: index + 1 }));
}

export async function upgradePlanCommand(flags: PlanFlags): Promise<number> {
  const { context, result } = await runScanCommand(flags);
  const plan = buildUpgradePlan(result.findings);

  if (flags.format === 'json' || flags.json) {
    process.stdout.write(
      `${JSON.stringify({ plan, note: 'Deplyze does not apply these changes.' }, null, 2)}\n`,
    );
    return 0;
  }

  printHeading('Deplyze upgrade plan');
  if (plan.length === 0) {
    process.stdout.write('No upgrades are recommended from the current findings.\n');
    return 0;
  }

  const compatible = plan.filter((step) => !step.breaking);
  const breaking = plan.filter((step) => step.breaking);

  const render = (step: PlanStep): void => {
    const risk = step.breaking
      ? 'HIGH — semver-major, review before applying'
      : 'LOW — compatible per semver range';
    process.stdout.write(`  ${step.order}. ${step.package}  ${step.from} -> ${step.to}\n`);
    process.stdout.write(`     risk: ${risk}\n`);
    process.stdout.write(`     why:  ${[...new Set(step.reasons)].join('; ')}\n`);
    process.stdout.write(
      `     cmd:  npm install ${step.package}@${step.breaking ? step.to : `^${step.to}`}\n`,
    );
    if (step.breaking) {
      process.stdout.write(
        '     review: changelog, peer dependency ranges, Node version support, test suite\n',
      );
    }
    process.stdout.write('\n');
  };

  if (compatible.length > 0) {
    process.stdout.write(`Compatible upgrades (${compatible.length})\n\n`);
    compatible.forEach(render);
  }
  if (breaking.length > 0) {
    process.stdout.write(`Major upgrades requiring review (${breaking.length})\n\n`);
    breaking.forEach(render);
  }

  process.stdout.write(
    'Deplyze does not modify package.json, lockfiles or node_modules. Apply these steps yourself.\n',
  );

  if (flags.ai) {
    assertAiEnabled(context.config);
    const runner = new AiRunner({ config: context.config, logger: context.logger });
    const ai = await runner.upgradePlan(result);
    process.stdout.write(
      `\nAI-generated sequencing advice (${ai.provider}/${ai.model})\n${'─'.repeat(72)}\n${ai.text}\n`,
    );
    process.stdout.write(`(${ai.disclosure})\n`);
  }

  const hasBlocking = breaking.length > 0;
  return hasBlocking && flags.failOn?.includes('major') ? 1 : 0;
}

export async function fixCommand(flags: PlanFlags): Promise<number> {
  const { result } = await runScanCommand(flags);
  printHeading('Deplyze fix (dry run)');

  const actionable = result.findings.filter((finding) => finding.remediation);
  if (actionable.length === 0) {
    process.stdout.write('Nothing to fix.\n');
    return 0;
  }

  process.stdout.write(
    'Deplyze never edits manifests or lockfiles. The commands below are what you (or your agent) would run.\n\n',
  );
  const commands = new Set<string>();
  for (const finding of actionable) {
    if (finding.remediation?.command) commands.add(finding.remediation.command);
  }
  if (commands.size === 0) {
    process.stdout.write('No automated commands are available; manual steps are required:\n\n');
    for (const finding of actionable.slice(0, 25)) {
      process.stdout.write(`  ${finding.id}  ${finding.title}\n`);
      if (finding.remediation) process.stdout.write(`    ${finding.remediation.summary}\n`);
    }
    return 0;
  }
  for (const command of commands) process.stdout.write(`  ${command}\n`);
  process.stdout.write(`\n${commands.size} command(s) across ${actionable.length} finding(s).\n`);
  process.stdout.write('Re-run `deplyze scan` after applying them.\n');
  return 0;
}
