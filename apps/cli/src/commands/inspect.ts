import { DeplyzeError, ErrorCode, assertSafePackageName, compareVersions } from '@deplyze/core';
import { RegistryClient, detectTyposquat } from '@deplyze/scanners';
import { createContext, type GlobalFlags } from '../context.js';
import { printHeading } from '../output.js';

export interface PackageFlags extends GlobalFlags {
  version?: string;
  /** `--package-version` on the CLI (avoids clashing with the global --version). */
  packageVersion?: string;
}

interface InspectionResult {
  name: string;
  exists: boolean;
  latest?: string;
  resolvedVersion?: string;
  license?: string;
  deprecated?: string;
  publishedVersions?: number;
  firstPublished?: string;
  ageDays?: number;
  maintainers?: number;
  weeklyDownloads?: number;
  lifecycleScripts?: Record<string, string>;
  dependencyCount?: number;
  dependencies?: string[];
  repository?: string;
  typosquat?: ReturnType<typeof detectTyposquat>;
}

export async function inspectPackage(
  name: string,
  options: { version?: string; offline?: boolean; checkDownloads?: boolean; cacheDirectory?: string },
): Promise<InspectionResult> {
  assertSafePackageName(name);
  const registry = new RegistryClient({
    offline: options.offline ?? false,
    ...(options.cacheDirectory ? { cacheDirectory: options.cacheDirectory } : {}),
  });
  const metadata = await registry.getMetadata(name);
  const typosquat = detectTyposquat({ name });

  if (!metadata) {
    return { name, exists: false, ...(typosquat ? { typosquat } : {}) };
  }

  const target = options.version
    ? metadata.versions.find((entry) => entry.version === options.version)
    : metadata.latest
      ? metadata.versions.find((entry) => entry.version === metadata.latest)
      : undefined;

  const created = metadata.time?.created;
  const ageDays = created
    ? Math.round((Date.now() - Date.parse(created)) / (1000 * 60 * 60 * 24))
    : undefined;
  const dependencies = Object.keys(target?.dependencies ?? {});
  const lifecycle = target?.scripts
    ? Object.fromEntries(
        Object.entries(target.scripts).filter(([key]) =>
          ['preinstall', 'install', 'postinstall', 'prepare', 'prepublish', 'prepublishOnly'].includes(key),
        ),
      )
    : {};

  const weeklyDownloads =
    options.checkDownloads === false || options.offline
      ? undefined
      : await registry.weeklyDownloads(name).catch(() => undefined);

  const result: InspectionResult = {
    name,
    exists: true,
    publishedVersions: metadata.versions.length,
  };
  if (metadata.latest) result.latest = metadata.latest;
  if (target?.version) result.resolvedVersion = target.version;
  if (target?.license) result.license = target.license;
  if (target?.deprecated) result.deprecated = target.deprecated;
  if (created) result.firstPublished = created;
  if (ageDays !== undefined) result.ageDays = ageDays;
  if (metadata.maintainers) result.maintainers = metadata.maintainers.length;
  if (weeklyDownloads !== undefined) result.weeklyDownloads = weeklyDownloads;
  if (Object.keys(lifecycle).length > 0) result.lifecycleScripts = lifecycle;
  result.dependencyCount = dependencies.length;
  if (dependencies.length > 0) result.dependencies = dependencies.slice(0, 40);
  if (metadata.repository) result.repository = metadata.repository;
  if (typosquat) result.typosquat = typosquat;
  return result;
}

export function renderInspection(inspection: InspectionResult): string {
  const lines: string[] = [];
  if (!inspection.exists) {
    lines.push(`${inspection.name}: NOT FOUND on the npm registry.`);
    lines.push('');
    lines.push('This means one of:');
    lines.push('  - the package does not exist (verify the spelling),');
    lines.push('  - it is private and not visible without credentials, or');
    lines.push('  - the registry was unreachable.');
    lines.push('');
    lines.push('Deplyze reports this as UNKNOWN, not as safe.');
    if (inspection.typosquat) {
      lines.push('');
      lines.push(
        `Name similarity: "${inspection.name}" resembles "${inspection.typosquat.target}" ` +
          `(distance ${inspection.typosquat.distance}, confidence ${inspection.typosquat.confidence}).`,
      );
    }
    return `${lines.join('\n')}\n`;
  }

  lines.push(`${inspection.name}${inspection.resolvedVersion ? `@${inspection.resolvedVersion}` : ''}`);
  lines.push('');
  lines.push(`  latest version     ${inspection.latest ?? 'unknown'}`);
  lines.push(`  license            ${inspection.license ?? 'unknown (not declared)'}`);
  lines.push(`  deprecated         ${inspection.deprecated ? `yes — ${inspection.deprecated}` : 'no'}`);
  lines.push(`  published versions ${inspection.publishedVersions ?? 'unknown'}`);
  if (inspection.firstPublished) {
    lines.push(`  first published    ${inspection.firstPublished} (${inspection.ageDays} days ago)`);
  }
  lines.push(`  maintainers        ${inspection.maintainers ?? 'unknown'}`);
  lines.push(`  weekly downloads   ${inspection.weeklyDownloads ?? 'not queried'}`);
  lines.push(`  direct deps        ${inspection.dependencyCount ?? 0}`);
  if (inspection.repository) lines.push(`  repository         ${inspection.repository}`);

  if (inspection.lifecycleScripts && Object.keys(inspection.lifecycleScripts).length > 0) {
    lines.push('');
    lines.push('  Lifecycle scripts (inspected as text, never executed):');
    for (const [script, command] of Object.entries(inspection.lifecycleScripts)) {
      lines.push(`    ${script}: ${command.length > 160 ? `${command.slice(0, 160)}…` : command}`);
    }
  }

  if (inspection.dependencies && inspection.dependencies.length > 0) {
    lines.push('');
    lines.push(`  Direct dependencies: ${inspection.dependencies.join(', ')}`);
  }

  lines.push('');
  if (inspection.typosquat) {
    lines.push('  NAME SIMILARITY (heuristic, not a verdict)');
    lines.push(`    resembles ${inspection.typosquat.target} — ${inspection.typosquat.reason}`);
    lines.push(`    confidence: ${inspection.typosquat.confidence}`);
    lines.push(`    ${inspection.typosquat.recommendedAction}`);
    lines.push('');
  }

  lines.push('  Assessment');
  const concerns: string[] = [];
  if (inspection.deprecated) concerns.push('the package is deprecated by its publisher');
  if (inspection.typosquat) concerns.push('the name is similar to a popular package');
  if ((inspection.ageDays ?? Number.POSITIVE_INFINITY) < 30)
    concerns.push('it was first published less than 30 days ago');
  if ((inspection.maintainers ?? 1) <= 1) concerns.push('it lists a single maintainer');
  if (!inspection.license) concerns.push('it declares no license');
  if (inspection.lifecycleScripts && Object.keys(inspection.lifecycleScripts).length > 0) {
    concerns.push('it runs install-time scripts');
  }
  if (concerns.length === 0) {
    lines.push('    No automated concerns were detected. Deplyze does not certify packages as safe —');
    lines.push('    review the source and publisher before adding a new dependency.');
  } else {
    lines.push(`    ${concerns.length} item(s) warrant review:`);
    for (const concern of concerns) lines.push(`      - ${concern}`);
  }
  return `${lines.join('\n')}\n`;
}

export async function packageCommand(name: string, flags: PackageFlags): Promise<number> {
  const context = await createContext(flags);
  const requestedVersion = flags.packageVersion ?? flags.version;
  const inspection = await inspectPackage(name, {
    ...(requestedVersion ? { version: requestedVersion } : {}),
    offline: context.config.scan.offline,
    cacheDirectory: `${context.config.scan.cache.directory}/registry`,
  });
  if (flags.format === 'json' || flags.json) {
    process.stdout.write(`${JSON.stringify(inspection, null, 2)}\n`);
    return 0;
  }
  printHeading('Deplyze package inspection');
  process.stdout.write(renderInspection(inspection));
  return inspection.exists ? 0 : 0;
}

export interface GuardFlags extends PackageFlags {
  failOn?: string[];
}

export type GuardDecision = 'ALLOW' | 'WARN' | 'BLOCK';

export interface GuardOutcome {
  decision: GuardDecision;
  reasons: string[];
  inspection: InspectionResult;
}

/** Extract package names from `npm install <pkg> ...` style commands. */
export function parseInstallCommand(argv: string[]): { manager: string; packages: string[] } | undefined {
  if (argv.length === 0) return undefined;
  const manager = argv[0] as string;
  if (!['npm', 'pnpm', 'yarn', 'bun', 'npx', 'pnpx', 'bunx'].includes(manager)) return undefined;
  const subcommand = argv[1];
  const isInstall =
    subcommand === 'install' || subcommand === 'add' || subcommand === 'i' || manager.endsWith('x');
  if (!isInstall) return undefined;
  const startIndex = manager.endsWith('x') ? 1 : 2;
  const packages = argv
    .slice(startIndex)
    .filter((token) => !token.startsWith('-'))
    // Strip version specifiers (`lodash@4.17.21`) but keep scopes intact.
    .map((token) => {
      const at = token.lastIndexOf('@');
      if (at > 0) return token.slice(0, at);
      return token;
    })
    .filter((token) => token.length > 0 && token !== '.' && !token.includes('://'));
  return { manager, packages };
}

/**
 * Decide whether a proposed install should proceed.
 *
 * The guard is advisory by default: it blocks only when the configured
 * `packages.denied` policy is violated, because silently blocking installs
 * would break workflows Deplyze does not own.
 */
export function decideGuard(
  inspection: InspectionResult,
  policy: { deniedPackages: string[]; blockOnTyposquat?: boolean; blockOnDeprecated?: boolean },
): GuardOutcome {
  const reasons: string[] = [];
  let decision: GuardDecision = 'ALLOW';

  if (policy.deniedPackages.includes(inspection.name)) {
    reasons.push(`"${inspection.name}" is listed in packages.denied in your Deplyze policy.`);
    decision = 'BLOCK';
  }
  if (!inspection.exists) {
    reasons.push(
      'The package could not be resolved on the npm registry. Installing an unverifiable name is not safe.',
    );
    decision = 'BLOCK';
  }
  if (inspection.typosquat) {
    reasons.push(
      `The name resembles "${inspection.typosquat.target}" (${inspection.typosquat.confidence} confidence): ${inspection.typosquat.reason}`,
    );
    if (policy.blockOnTyposquat && decision !== 'BLOCK') decision = 'BLOCK';
    else if (decision === 'ALLOW') decision = 'WARN';
  }
  if (inspection.deprecated) {
    reasons.push(`The package is deprecated: ${inspection.deprecated}`);
    if (policy.blockOnDeprecated && decision !== 'BLOCK') decision = 'BLOCK';
    else if (decision === 'ALLOW') decision = 'WARN';
  }
  if ((inspection.ageDays ?? Number.POSITIVE_INFINITY) < 30) {
    reasons.push(`The package was first published ${inspection.ageDays} day(s) ago.`);
    if (decision === 'ALLOW') decision = 'WARN';
  }
  if (!inspection.license) {
    reasons.push('No license is declared.');
    if (decision === 'ALLOW') decision = 'WARN';
  }
  if (inspection.lifecycleScripts && Object.keys(inspection.lifecycleScripts).length > 0) {
    reasons.push(
      `It runs install-time scripts (${Object.keys(inspection.lifecycleScripts).join(', ')}); these execute with your privileges.`,
    );
    if (decision === 'ALLOW') decision = 'WARN';
  }
  if ((inspection.dependencyCount ?? 0) > 100) {
    reasons.push(
      `It declares ${inspection.dependencyCount} direct dependencies, which substantially expands your supply chain.`,
    );
    if (decision === 'ALLOW') decision = 'WARN';
  }

  return { decision, reasons, inspection };
}

export async function guardCommand(packages: string[], flags: GuardFlags): Promise<number> {
  const context = await createContext(flags);
  if (packages.length === 0) {
    throw new DeplyzeError(ErrorCode.DEPLYZE_E_USAGE, 'No package specified.', {
      hint: 'Use `deplyze guard --package <name>` or `deplyze guard npm install <name>`.',
    });
  }

  const blockOnTyposquat = (flags.failOn ?? []).includes('typosquat');
  let worst: GuardDecision = 'ALLOW';
  const details: GuardOutcome[] = [];

  for (const name of packages) {
    const inspection = await inspectPackage(name, {
      offline: context.config.scan.offline,
      cacheDirectory: `${context.config.scan.cache.directory}/registry`,
    });
    const outcome = decideGuard(inspection, {
      deniedPackages: context.config.packages.denied,
      ...(blockOnTyposquat ? { blockOnTyposquat } : {}),
    });
    details.push(outcome);
    if (outcome.decision === 'BLOCK') worst = 'BLOCK';
    else if (outcome.decision === 'WARN' && worst === 'ALLOW') worst = 'WARN';
  }

  if (flags.format === 'json' || flags.json) {
    process.stdout.write(`${JSON.stringify({ decision: worst, packages: details }, null, 2)}\n`);
    return worst === 'BLOCK' ? 1 : 0;
  }

  printHeading('Deplyze pre-install guard');
  for (const outcome of details) {
    process.stdout.write(`\n  ${outcome.decision}  ${outcome.inspection.name}\n`);
    if (outcome.reasons.length === 0) {
      process.stdout.write('    No automated concerns detected.\n');
    } else {
      for (const reason of outcome.reasons) process.stdout.write(`    - ${reason}\n`);
    }
  }
  process.stdout.write(
    `\n  Decision: ${worst}\n` +
      (worst === 'BLOCK'
        ? '  Deplyze did not run the install command. Remove the package or update your policy to proceed.\n'
        : worst === 'WARN'
          ? '  Review the items above before installing.\n'
          : '  No blocking policy matched.\n'),
  );
  process.stdout.write('  Deplyze never executes the package manager on your behalf.\n');
  return worst === 'BLOCK' ? 1 : 0;
}

export { compareVersions };
