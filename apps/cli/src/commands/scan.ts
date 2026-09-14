import { getReporter } from '@deplyze/reporters';
import { formatViolations, evaluatePolicy } from '@deplyze/policies';
import { applyPolicyAndExitCode, filterFindings, runScanCommand, type ScanFlags } from './shared.js';
import { assertWritablePath, emit, printHeading, resolveFormat } from '../output.js';

export async function scanCommand(flags: ScanFlags): Promise<number> {
  // `deplyze scan --ci` is a documented shorthand for `deplyze ci`.
  if (flags.ci) return ciCommand(flags);
  const { context, result } = await runScanCommand(flags);
  const format = resolveFormat(flags);
  const filtered = filterFindings(result, flags);

  if (flags.output) assertWritablePath(result.project.root, flags.output);

  await emit(filtered, {
    format,
    ...(flags.output ? { file: flags.output } : {}),
    color: context.colorMode,
    maxFindings: flags.maxFindings ?? 12,
    includeInfo: flags.includeInfo !== false,
    root: result.project.root,
  });

  if (format === 'terminal') {
    const evaluation = evaluatePolicy(result);
    if (evaluation.suppressed.length > 0) {
      process.stdout.write(`\n  ${evaluation.suppressed.length} finding(s) suppressed by configuration.\n`);
    }
    if (evaluation.expiredSuppressions.length > 0) {
      process.stdout.write(
        `  WARNING: ${evaluation.expiredSuppressions.length} suppression(s) have expired and no longer apply: ` +
          `${evaluation.expiredSuppressions.map((entry) => entry.id).join(', ')}\n`,
      );
    }
    if (evaluation.violations.length > 0) {
      process.stdout.write(`\n${formatViolations(evaluation)}\n`);
    }
  }

  const { exitCode } = applyPolicyAndExitCode(result, flags);
  return exitCode;
}

export async function securityCommand(flags: ScanFlags): Promise<number> {
  return scanCommand({ ...flags, category: 'vulnerability' });
}

export async function outdatedCommand(flags: ScanFlags): Promise<number> {
  return withCategory(flags, 'outdated');
}

export async function unusedCommand(flags: ScanFlags): Promise<number> {
  return withCategory(flags, 'unused');
}

export async function duplicatesCommand(flags: ScanFlags): Promise<number> {
  return withCategory(flags, 'duplicate');
}

export async function licensesCommand(flags: ScanFlags): Promise<number> {
  return withCategory(flags, 'license');
}

async function withCategory(flags: ScanFlags, category: string): Promise<number> {
  const { context, result } = await runScanCommand(flags);
  const filtered = filterFindings(result, { ...flags, category });
  await emit(filtered, {
    format: resolveFormat(flags),
    ...(flags.output ? { file: flags.output } : {}),
    color: context.colorMode,
    maxFindings: flags.maxFindings ?? 40,
    includeInfo: true,
    root: result.project.root,
  });
  if (resolveFormat(flags) === 'terminal' && filtered.findings.length === 0) {
    process.stdout.write(`\n  No ${category} findings.\n`);
  }
  if (flags.output) assertWritablePath(result.project.root, flags.output);
  const { exitCode } = applyPolicyAndExitCode(result, flags);
  return exitCode;
}

export async function reportCommand(flags: ScanFlags & { format: string; output?: string }): Promise<number> {
  const { context, result } = await runScanCommand(flags);
  const reporter = getReporter(flags.format);
  const file = flags.output ?? `deplyze-report.${reporter.extension}`;
  assertWritablePath(result.project.root, file);
  await emit(result, {
    format: flags.format,
    file,
    color: context.colorMode,
    root: result.project.root,
  });
  return 0;
}

export async function ciCommand(flags: ScanFlags): Promise<number> {
  const { context, result } = await runScanCommand(flags);
  const format =
    flags.format ?? (result.config.ci.sarifFile ? 'sarif' : result.config.ci.format) ?? 'terminal';
  const file = flags.output ?? result.config.ci.sarifFile ?? undefined;

  if (format === 'terminal') {
    printHeading(`Deplyze CI — ${result.project.name}`);
  }

  await emit(result, {
    format,
    ...(file ? { file } : {}),
    color: flags.color === 'always' ? 'always' : 'never',
    root: result.project.root,
    quiet: format !== 'terminal' && !file ? false : false,
  });

  const evaluation = evaluatePolicy(result);
  if (format === 'terminal') {
    process.stdout.write(`\n${formatViolations(evaluation)}\n`);
    if (evaluation.expiredSuppressions.length > 0) {
      process.stdout.write(
        `warning: ${evaluation.expiredSuppressions.length} suppression(s) expired: ` +
          `${evaluation.expiredSuppressions.map((entry) => entry.id).join(', ')}\n`,
      );
    }
  } else {
    process.stderr.write(
      evaluation.passed
        ? `deplyze: policy passed (${result.summary.total} findings)\n`
        : `deplyze: ${evaluation.violations.length} policy violation(s)\n${formatViolations(evaluation)}\n`,
    );
  }

  void context;
  const { exitCode } = applyPolicyAndExitCode(result, flags);
  return exitCode;
}

export async function policyCommand(flags: ScanFlags): Promise<number> {
  const { result } = await runScanCommand(flags);
  const evaluation = evaluatePolicy(result);
  const payload = {
    passed: evaluation.passed,
    exitCode: evaluation.exitCode,
    violations: evaluation.violations,
    activeFindings: evaluation.active.length,
    suppressed: evaluation.suppressed.map((entry) => ({
      id: entry.finding.id,
      rule: entry.suppression.id,
      reason: entry.suppression.reason,
      expires: entry.suppression.expires,
    })),
    expiredSuppressions: evaluation.expiredSuppressions,
    unusedSuppressions: evaluation.unusedSuppressions,
    thresholds: {
      failOn: result.config.ci.failOn.length > 0 ? result.config.ci.failOn : result.config.security.failOn,
      maxCritical: result.config.security.vulnerabilities.maxCritical,
      maxHigh: result.config.security.vulnerabilities.maxHigh,
      deniedLicenses: result.config.licenses.denied,
      deniedPackages: result.config.packages.denied,
      deprecatedFails: result.config.security.deprecated.fail,
    },
  };
  if (resolveFormat(flags) === 'json') {
    process.stdout.write(`${JSON.stringify(payload, null, 2)}\n`);
  } else {
    printHeading('Deplyze policy check');
    process.stdout.write(`${formatViolations(evaluation)}\n`);
    if (evaluation.expiredSuppressions.length > 0) {
      process.stdout.write(
        `\nExpired suppressions (no longer applied):\n${evaluation.expiredSuppressions
          .map((entry) => `  - ${entry.id}: ${entry.reason}`)
          .join('\n')}\n`,
      );
    }
    if (evaluation.unusedSuppressions.length > 0) {
      process.stdout.write(
        `\nSuppressions that matched nothing (candidates for removal):\n${evaluation.unusedSuppressions
          .map((entry) => `  - ${entry.id}`)
          .join('\n')}\n`,
      );
    }
  }
  return applyPolicyAndExitCode(result, flags).exitCode;
}
