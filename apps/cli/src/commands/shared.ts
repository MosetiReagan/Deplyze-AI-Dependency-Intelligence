import { DeplyzeError, ErrorCode, type Severity } from '@deplyze/core';
import { runScan, type ScanResult } from '@deplyze/scanners';
import { evaluatePolicy } from '@deplyze/policies';
import { createContext, type CommandContext, type GlobalFlags } from '../context.js';

export interface ScanFlags extends GlobalFlags {
  format?: string;
  json?: boolean;
  sarif?: boolean;
  severity?: string;
  category?: string;
  failOn?: string[];
  noPolicy?: boolean;
  includeInfo?: boolean;
  maxFindings?: number;
  output?: string;
  only?: string[];
  ci?: boolean;
}

export interface ScanCommandResult {
  context: CommandContext;
  result: ScanResult;
}

export async function runScanCommand(flags: ScanFlags): Promise<ScanCommandResult> {
  const context = await createContext(flags);
  if (flags.severity) {
    const severity = flags.severity.toLowerCase();
    if (!['critical', 'high', 'medium', 'low', 'info', 'unknown'].includes(severity)) {
      throw new DeplyzeError(ErrorCode.DEPLYZE_E_USAGE, `Unknown severity: ${flags.severity}`, {
        hint: 'Valid severities: critical, high, medium, low, info.',
      });
    }
  }
  const result = await runScan({
    root: context.root,
    config: context.config,
    logger: context.logger,
    ...(flags.only ? { only: flags.only } : {}),
  });
  return { context, result };
}

export function filterFindings(
  result: ScanResult,
  flags: { severity?: string; category?: string; includeInfo?: boolean },
): ScanResult {
  const order = ['critical', 'high', 'medium', 'low', 'info', 'unknown'];
  let findings = result.findings;
  if (flags.severity) {
    const threshold = order.indexOf(flags.severity.toLowerCase());
    findings = findings.filter((finding) => order.indexOf(finding.severity) <= threshold);
  }
  if (flags.category) {
    findings = findings.filter((finding) => finding.category === flags.category);
  }
  if (flags.includeInfo === false) {
    findings = findings.filter((finding) => finding.severity !== 'info');
  }
  return { ...result, findings };
}

/**
 * Evaluate policy and return the process exit code.
 *
 * `--fail-on` on the command line overrides the configured thresholds for this
 * run only, which is how CI jobs customise strictness per pipeline.
 */
export function applyPolicyAndExitCode(
  result: ScanResult,
  flags: { failOn?: string[]; noPolicy?: boolean },
): { exitCode: 0 | 1; violations: string[] } {
  if (flags.noPolicy) return { exitCode: 0, violations: [] };
  let effective = result;
  if (flags.failOn && flags.failOn.length > 0) {
    const failOn = flags.failOn.map((value) => value.toLowerCase() as Severity);
    effective = {
      ...result,
      config: {
        ...result.config,
        ci: { ...result.config.ci, failOn },
      },
    };
  }
  const evaluation = evaluatePolicy(effective);
  return {
    exitCode: evaluation.exitCode,
    violations: evaluation.violations.map((violation) => `[${violation.rule}] ${violation.message}`),
  };
}
