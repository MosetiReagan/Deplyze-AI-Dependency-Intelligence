import { Command, Option } from 'commander';
import { DeplyzeError, ErrorCode, formatError, isDeplyzeError } from '@deplyze/core';
import { createContext, type GlobalFlags } from './context.js';
import {
  scanCommand,
  securityCommand,
  outdatedCommand,
  unusedCommand,
  duplicatesCommand,
  licensesCommand,
  reportCommand,
  ciCommand,
  policyCommand,
} from './commands/scan.js';
import { graphCommand } from './commands/graph.js';
import { guardCommand, packageCommand, parseInstallCommand } from './commands/inspect.js';
import { explainCommand } from './commands/explain.js';
import { fixCommand, upgradePlanCommand } from './commands/remediate.js';
import { sbomCommand } from './commands/sbom.js';
import { mcpCommand } from './commands/mcp.js';
import { doctorCommand } from './commands/doctor.js';
import { AiRunner, assertAiEnabled } from '@deplyze/ai';
import { runScanCommand } from './commands/shared.js';

export const VERSION = '0.1.0';

function globalOptions(command: Command, options: { omitFormat?: boolean } = {}): Command {
  command
    .option('--path <dir>', 'project directory to analyse (defaults to the current directory)')
    .option('--config <file>', 'path to a Deplyze configuration file')
    .option('--offline', 'use only cached advisory and registry data; never make a network request')
    .option('--no-network', 'disable all network access (registry metadata and advisories)')
    .addOption(new Option('--color <mode>', 'colour output').choices(['auto', 'always', 'never']))
    .option('--quiet', 'suppress non-essential output')
    .option('--verbose', 'verbose diagnostics')
    .option('--debug', 'debug diagnostics (includes timestamps)');
  void options;
  return command;
}

function scanOptions(command: Command): Command {
  return command
    .option('--format <format>', 'output format: terminal, json, markdown, sarif, html')
    .option('--json', 'shorthand for --format json')
    .option('--sarif', 'shorthand for --format sarif')
    .option('--severity <level>', 'only show findings at or above this severity')
    .option('--category <category>', 'only show findings in this category')
    .option('--fail-on <severity...>', 'override the configured failure threshold for this run')
    .option('--no-policy', 'never exit with a policy-violation status')
    .option('--no-info', 'exclude informational findings')
    .option('--max-findings <n>', 'maximum findings to render in the terminal summary', (value) =>
      Number(value),
    )
    .option('--ci', 'CI mode: emit the configured CI format and apply the policy exit code')
    .option('--output <file>', 'write the report to a file instead of stdout');
}

function collectFlags(command: Command): GlobalFlags & Record<string, unknown> {
  const root = command.parent ?? command;
  const merged = {
    ...(root.opts() as GlobalFlags),
    ...(command.opts() as Record<string, unknown>),
  } as GlobalFlags & Record<string, unknown>;
  // Commander stores negatable options as `policy: false` / `info: false`.
  // Normalize them to the names the command handlers read so the flags
  // actually take effect.
  if ((merged as { policy?: boolean }).policy === false) merged.noPolicy = true;
  if ((merged as { info?: boolean }).info === false) merged.includeInfo = false;
  return merged;
}

export function buildProgram(): Command {
  const program = new Command();

  program
    .name('deplyze')
    .description(
      'Deplyze — AI Dependency Intelligence. Evidence-based dependency and software supply-chain analysis.',
    )
    .version(VERSION, '--version', 'print the Deplyze version')
    .helpOption('-h, --help', 'show help')
    .showSuggestionAfterError(true)
    .showHelpAfterError('(run `deplyze --help` for usage)')
    .configureOutput({
      writeErr: (str) => process.stderr.write(str),
      outputError: (str, write) => write(str),
    })
    .exitOverride();

  globalOptions(program);

  const scan = program.command('scan').description('Analyse the project and report findings');
  scanOptions(scan);
  scan.action(async () => {
    const flags = collectFlags(scan);
    await run(scan, () => scanCommand(flags));
  });

  for (const alias of ['audit', 'analyze', 'analyse']) {
    const command = program
      .command(alias, { hidden: alias !== 'audit' })
      .description('Alias for `deplyze scan`');
    scanOptions(command);
    command.action(async () => {
      const flags = collectFlags(command);
      await run(command, () => scanCommand(flags));
    });
  }

  const security = program.command('security').description('Report vulnerabilities only');
  scanOptions(security);
  security.action(async () => {
    const flags = collectFlags(security);
    await run(security, () => securityCommand(flags));
  });

  const outdated = program.command('outdated').description('Report outdated dependencies');
  scanOptions(outdated);
  outdated.action(async () => {
    const flags = collectFlags(outdated);
    await run(outdated, () => outdatedCommand(flags));
  });

  const unused = program.command('unused').description('Report likely-unused dependencies');
  scanOptions(unused);
  unused.action(async () => {
    const flags = collectFlags(unused);
    await run(unused, () => unusedCommand(flags));
  });

  const duplicates = program
    .command('duplicates')
    .description('Report packages resolved to multiple versions');
  scanOptions(duplicates);
  duplicates.action(async () => {
    const flags = collectFlags(duplicates);
    await run(duplicates, () => duplicatesCommand(flags));
  });

  const licenses = program
    .command('licenses')
    .description('Report license distribution and policy violations');
  scanOptions(licenses);
  licenses.action(async () => {
    const flags = collectFlags(licenses);
    await run(licenses, () => licensesCommand(flags));
  });

  const graph = program.command('graph').description('Print the resolved dependency graph');
  scanOptions(graph)
    .option('--package <name>', 'focus on a single package')
    .option('--depth <n>', 'maximum tree depth', (value) => Number(value))
    .option('--direction <direction>', 'dependents, dependencies or both')
    .option('--limit <n>', 'maximum entries per section', (value) => Number(value));
  graph.action(async () => {
    const flags = collectFlags(graph);
    await run(graph, () => graphCommand(flags as never));
  });

  const pkg = program
    .command('package <name>')
    .description('Inspect a package on the registry before installing it');
  globalOptions(pkg).option('--package-version <version>', 'specific version to inspect');
  pkg.action(async (name: string) => {
    const flags = collectFlags(pkg);
    await run(pkg, () => packageCommand(name, flags as never));
  });

  const guard = program
    .command('guard [command...]')
    .description('Check a package before installing it (ALLOW / WARN / BLOCK)')
    .allowUnknownOption(true)
    .option('--package <name...>', 'package name(s) to check')
    .option('--fail-on <rule...>', 'rules that should block: typosquat, deprecated');
  globalOptions(guard);
  guard.action(async (commandArgs: string[]) => {
    const flags = collectFlags(guard) as never as { package?: string[]; failOn?: string[] };
    const options = guard.opts() as { package?: string[]; failOn?: string[] };
    let packages = options.package ?? [];
    if (packages.length === 0 && commandArgs.length > 0) {
      const parsed = parseInstallCommand(commandArgs);
      if (!parsed) {
        throw new DeplyzeError(
          ErrorCode.DEPLYZE_E_USAGE,
          `Could not interpret the install command: ${commandArgs.join(' ')}`,
          {
            hint: 'Use `deplyze guard --package <name>` or `deplyze guard npm install <name>`.',
            details: { flags },
          },
        );
      }
      packages = parsed.packages;
    }
    await run(guard, () =>
      guardCommand(packages, { ...flags, ...(options.failOn ? { failOn: options.failOn } : {}) } as never),
    );
  });

  const explain = program.command('explain <findingId>').description('Explain a finding in detail');
  scanOptions(explain).option('--ai', 'request an AI-authored explanation (requires ai.enabled)');
  explain.action(async (findingId: string) => {
    const flags = collectFlags(explain);
    await run(explain, () => explainCommand(findingId, flags as never));
  });

  const upgradePlan = program.command('upgrade-plan').description('Produce an ordered upgrade plan');
  scanOptions(upgradePlan).option('--ai', 'add AI-authored sequencing advice');
  upgradePlan.action(async () => {
    const flags = collectFlags(upgradePlan);
    await run(upgradePlan, () => upgradePlanCommand(flags as never));
  });

  const fix = program
    .command('fix')
    .description('Show the commands that would resolve findings (dry run; never modifies files)');
  scanOptions(fix);
  fix.action(async () => {
    const flags = collectFlags(fix);
    await run(fix, () => fixCommand(flags as never));
  });

  // `deplyze remediate` is the documented name for the same dry-run plan.
  const remediate = program
    .command('remediate')
    .description('Alias for `deplyze fix`: show the commands that would resolve findings');
  scanOptions(remediate);
  remediate.action(async () => {
    const flags = collectFlags(remediate);
    await run(remediate, () => fixCommand(flags as never));
  });

  const aiReview = program
    .command('ai-review')
    .description('AI-authored review of the dependency posture (requires ai.enabled)');
  scanOptions(aiReview);
  aiReview.action(async () => {
    const flags = collectFlags(aiReview);
    await run(aiReview, async () => {
      const { context, result } = await runScanCommand(flags as never);
      assertAiEnabled(context.config);
      const runner = new AiRunner({ config: context.config, logger: context.logger });
      const ai = await runner.review(result);
      process.stdout.write(
        `AI-generated review (${ai.provider}/${ai.model})\n${'─'.repeat(72)}\n${ai.text}\n`,
      );
      process.stdout.write(
        `\n(${ai.disclosure})\nThis text is AI-generated. The deterministic findings are authoritative.\n`,
      );
      return 0;
    });
  });

  const sbom = program.command('sbom').description('Generate a software bill of materials');
  globalOptions(sbom)
    .option('--format <format>', 'SBOM format: cyclonedx or spdx', 'cyclonedx')
    .option('--json', 'emit the SBOM to stdout as JSON instead of a file')
    .option('--output <file>', 'output path');
  sbom.action(async () => {
    const flags = collectFlags(sbom);
    await run(sbom, () => sbomCommand(flags as never));
  });

  const policy = program.command('policy').description('Evaluate the configured CI policy');
  scanOptions(policy);
  policy.action(async () => {
    const flags = collectFlags(policy);
    await run(policy, () => policyCommand(flags));
  });

  const ci = program
    .command('ci')
    .description('CI mode: analyse, emit SARIF/JSON and set a deterministic exit code');
  scanOptions(ci);
  ci.action(async () => {
    const flags = collectFlags(ci);
    await run(ci, () => ciCommand(flags));
  });

  const report = program
    .command('report')
    .description('Generate a shareable report (markdown, html, json or sarif)');
  scanOptions(report);
  report.action(async () => {
    const flags = collectFlags(report);
    await run(report, () => reportCommand(flags as never));
  });

  const mcp = program.command('mcp').description('Run the Deplyze MCP server on stdio for AI coding agents');
  globalOptions(mcp);
  mcp.action(async () => {
    const flags = collectFlags(mcp);
    await run(mcp, () => mcpCommand(flags));
  });

  const doctor = program
    .command('doctor')
    .description('Check the environment, configuration and network reachability');
  globalOptions(doctor);
  doctor.action(async () => {
    const flags = collectFlags(doctor);
    await run(doctor, () => doctorCommand(flags));
  });

  const version = program.command('version').description('Print the Deplyze version and build information');
  version.action(async () => {
    const context = await createContext({ quiet: true }).catch(() => undefined);
    process.stdout.write(
      [
        `deplyze ${VERSION}`,
        `node   ${process.versions.node}`,
        `platform ${process.platform} ${process.arch}`,
        context?.config.configPath ? `config ${context.config.configPath}` : 'config defaults',
        '',
      ].join('\n'),
    );
  });

  return program;
}

/**
 * Run a command action and translate the outcome into an exit code.
 *
 * Never leaks a stack trace by default; `--debug` prints one for support.
 */
async function run(command: Command, action: () => Promise<number>): Promise<void> {
  try {
    const code = await action();
    process.exitCode = code;
  } catch (error) {
    const root = command.parent ?? command;
    const debug = Boolean((root.opts() as { debug?: boolean }).debug);
    process.stderr.write(`\n${formatError(error)}\n`);
    if (debug && error instanceof Error && error.stack) {
      process.stderr.write(`\n${error.stack}\n`);
    }
    if (isDeplyzeError(error)) {
      process.exitCode = (error as DeplyzeError).exitCode;
    } else {
      process.exitCode = 2;
    }
  }
}
