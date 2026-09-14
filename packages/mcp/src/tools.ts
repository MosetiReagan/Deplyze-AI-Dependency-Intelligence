import { DeplyzeError, ErrorCode, assertSafePackageName, compareVersions } from '@deplyze/core';
import { RegistryClient, detectTyposquat } from '@deplyze/scanners';
import { evaluatePolicy } from '@deplyze/policies';
import { generateSbom, type SbomFormat } from '@deplyze/sbom';
import { packageCount, type ScanResult } from '@deplyze/scanners';
import type { ScanCache } from './cache.js';

export interface ToolResult {
  /** Structured payload returned to the agent. */
  data: Record<string, unknown>;
  /** Human-readable summary, also returned as MCP text content. */
  text: string;
  isError?: boolean;
}

function summaryOf(result: ScanResult): Record<string, unknown> {
  return {
    project: {
      name: result.project.name,
      version: result.project.version,
      manager: result.project.manager,
      workspaces: result.project.workspaces.map((workspace) => workspace.path),
      lockfiles: result.project.lockfiles.map((lockfile) => ({
        path: lockfile.path,
        manager: lockfile.manager,
        parsed: lockfile.parsed,
        resolvedPackages: lockfile.resolvedPackages,
      })),
    },
    counts: result.summary,
    health: {
      overall: result.risk.overall,
      band: result.risk.band,
      categories: Object.fromEntries(
        result.risk.categories.map((category) => [category.category, category.score]),
      ),
    },
    graph: result.stats,
    evidenceQuality: {
      advisorySource: result.config.advisories.enabled ? 'osv' : 'disabled',
      registrySkipped: result.diagnostics.registryPackagesMissing,
      networkUsed: result.diagnostics.usedNetwork,
      sourceFilesScanned: result.diagnostics.sourceFilesScanned,
    },
  };
}

function findingPayload(result: ScanResult, limit = 50): Array<Record<string, unknown>> {
  return result.findings.slice(0, limit).map((finding) => ({
    id: finding.id,
    severity: finding.severity,
    confidence: finding.confidence,
    category: finding.category,
    title: finding.title,
    package: finding.package,
    version: finding.version,
    advisoryId: finding.advisoryId,
    evidence: finding.evidence.map((entry) => entry.message).slice(0, 5),
    remediation: finding.remediation?.summary,
    paths: finding.paths?.slice(0, 2),
  }));
}

export async function toolScan(
  cache: ScanCache,
  args: { path?: string; severity?: string; category?: string; limit?: number },
): Promise<ToolResult> {
  const { result } = await cache.scan(args.path);
  let findings = result.findings;
  if (args.severity) {
    const order = ['critical', 'high', 'medium', 'low', 'info', 'unknown'];
    const minIndex = order.indexOf(args.severity);
    if (minIndex >= 0) {
      findings = findings.filter((finding) => order.indexOf(finding.severity) <= minIndex);
    }
  }
  if (args.category) {
    findings = findings.filter((finding) => finding.category === args.category);
  }
  const limit = Math.max(1, Math.min(args.limit ?? 50, 500));
  return {
    data: {
      summary: summaryOf(result),
      findings: findings.slice(0, limit).map((finding) => ({
        id: finding.id,
        severity: finding.severity,
        confidence: finding.confidence,
        category: finding.category,
        title: finding.title,
        package: finding.package,
        version: finding.version,
        advisoryId: finding.advisoryId,
        evidence: finding.evidence.map((entry) => entry.message).slice(0, 5),
        remediation: finding.remediation?.summary,
      })),
      truncated: findings.length > limit,
      note:
        'Deplyze reports only evidence it can verify. A package with no finding is not guaranteed safe, and an ' +
        'unreachable advisory source produces fewer findings rather than optimistic ones.',
    },
    text:
      `${result.project.name}: ${result.summary.total} finding(s) ` +
      `(critical ${result.summary.critical}, high ${result.summary.high}, medium ${result.summary.medium}, low ${result.summary.low}). ` +
      `Overall dependency health ${result.risk.overall}/100 (${result.risk.band}).`,
  };
}

export async function toolFindings(
  cache: ScanCache,
  args: { path?: string; severity?: string; category?: string; limit?: number },
): Promise<ToolResult> {
  return toolScan(cache, args);
}

export async function toolSecurity(cache: ScanCache, args: { path?: string }): Promise<ToolResult> {
  const { result } = await cache.scan(args.path);
  const security = result.findings.filter(
    (finding) => finding.category === 'vulnerability' || finding.category === 'security',
  );
  const advisories = [...new Set(security.map((finding) => finding.advisoryId).filter(Boolean))];
  return {
    data: {
      summary: summaryOf(result),
      advisorySource: 'osv.dev',
      advisoriesRetrieved: advisories,
      unresolvedAdvisories: result.diagnostics.unresolvedAdvisories,
      findings: security.map((finding) => ({
        id: finding.id,
        advisoryId: finding.advisoryId,
        severity: finding.severity,
        package: finding.package,
        version: finding.version,
        title: finding.title,
        confidence: finding.confidence,
        evidence: finding.evidence.map((entry) => entry.message),
        remediation: finding.remediation,
        paths: finding.paths,
      })),
      caveat:
        result.diagnostics.unresolvedAdvisories.length > 0
          ? 'Some advisories could not be retrieved; treat the result as incomplete.'
          : 'All advisory lookups completed. Absence of a finding does not prove a package is unaffected.',
    },
    text: `${security.length} security finding(s) across ${packageCount(result)} packages.`,
  };
}

export async function toolGraph(
  cache: ScanCache,
  args: {
    path?: string;
    package?: string;
    direction?: 'dependents' | 'dependencies' | 'both';
    limit?: number;
  },
): Promise<ToolResult> {
  const { result } = await cache.scan(args.path);
  const graph = result.graph;
  const limit = Math.max(1, Math.min(args.limit ?? 25, 200));

  if (!args.package) {
    return {
      data: {
        stats: result.stats,
        duplicates: [...graph.duplicates().keys()].slice(0, 50),
        topLevelDependencies: graph
          .nodes()
          .filter((node) => node.direct)
          .slice(0, limit)
          .map((node) => ({
            name: node.name,
            version: node.version,
            dev: node.dev,
            workspace: node.workspace,
            depth: node.depth,
            dependents: graph.transitiveDependents(node.id).length,
          })),
      },
      text: `Graph contains ${packageCount(result)} packages and ${result.stats.edgeCount} edges.`,
    };
  }

  const matches = graph.nodes().filter((node) => node.name === args.package);
  if (matches.length === 0) {
    return {
      data: { package: args.package, found: false, searched: packageCount(result) },
      text: `${args.package} is not present in the resolved dependency graph.`,
      isError: false,
    };
  }
  const direction = args.direction ?? 'both';
  const payload = matches.map((node) => {
    const entry: Record<string, unknown> = {
      name: node.name,
      version: node.version,
      direct: node.direct,
      dev: node.dev,
      optional: node.optional,
      depth: node.depth,
      paths: graph.pathsTo(node.id, 3).map((ids) => ids.join(' > ')),
    };
    if (direction === 'dependents' || direction === 'both') {
      entry.dependents = graph
        .transitiveDependents(node.id)
        .slice(0, limit)
        .map((dependent) => `${dependent.name}@${dependent.version}`);
    }
    if (direction === 'dependencies' || direction === 'both') {
      entry.dependencies = graph
        .transitiveDependencies(node.id)
        .slice(0, limit)
        .map((dependency) => `${dependency.name}@${dependency.version}`);
    }
    return entry;
  });
  return {
    data: { package: args.package, versions: matches.length, entries: payload },
    text: `${args.package} resolves to ${matches.length} version(s).`,
  };
}

export async function toolLicenses(cache: ScanCache, args: { path?: string }): Promise<ToolResult> {
  const { result } = await cache.scan(args.path);
  const licenses = new Map<string, string[]>();
  for (const node of result.graph.nodes()) {
    if (node.depth === 0) continue;
    const key = node.license ?? 'UNKNOWN';
    const list = licenses.get(key) ?? [];
    list.push(`${node.name}@${node.version}`);
    licenses.set(key, list);
  }
  const licenseFindings = result.findings.filter((finding) => finding.category === 'license');
  return {
    data: {
      summary: summaryOf(result),
      distribution: [...licenses.entries()]
        .sort((a, b) => b[1].length - a[1].length)
        .map(([license, packages]) => ({ license, count: packages.length, examples: packages.slice(0, 5) })),
      violations: licenseFindings.map((finding) => ({
        id: finding.id,
        severity: finding.severity,
        package: finding.package,
        version: finding.version,
        title: finding.title,
        evidence: finding.evidence.map((entry) => entry.message),
      })),
      policy: {
        allowed: result.config.licenses.allowed,
        denied: result.config.licenses.denied,
        unknown: result.config.licenses.unknown,
      },
      disclaimer:
        'Deplyze reports detected and undetected licenses. It does not provide legal advice and never assumes an unknown license is safe.',
    },
    text: `${licenseFindings.length} license finding(s); ${licenses.size} distinct license value(s) observed.`,
  };
}

export async function toolUpgradePlan(cache: ScanCache, args: { path?: string }): Promise<ToolResult> {
  const { result } = await cache.scan(args.path);
  const security = result.findings.filter((finding) => finding.category === 'vulnerability');
  const outdated = result.findings.filter((finding) => finding.category === 'outdated');
  const upgrades = new Map<
    string,
    { package: string; from: string; to: string; reason: string[]; breaking: boolean }
  >();
  for (const finding of [...security, ...outdated]) {
    for (const upgrade of finding.remediation?.upgrades ?? []) {
      const key = `${upgrade.package}@${upgrade.from}->${upgrade.to}`;
      const existing = upgrades.get(key);
      if (existing) {
        existing.reason.push(finding.title);
      } else {
        upgrades.set(key, {
          package: upgrade.package,
          from: upgrade.from,
          to: upgrade.to,
          reason: [finding.title],
          breaking: upgrade.breaking,
        });
      }
    }
  }
  const plan = [...upgrades.values()].sort((a, b) => {
    if (a.breaking !== b.breaking) return a.breaking ? 1 : -1;
    return compareVersions(b.from, a.from);
  });
  return {
    data: {
      summary: summaryOf(result),
      upgrades: plan,
      caveat:
        'Deplyze does not execute upgrades. Compatibility risk is estimated from semver ranges only; major upgrades always require review.',
    },
    text: `${plan.length} recommended upgrade(s): ${plan.filter((entry) => !entry.breaking).length} compatible-range, ${plan.filter((entry) => entry.breaking).length} major.`,
  };
}

export async function toolPackage(
  cache: ScanCache,
  args: { name: string; version?: string; checkDownloads?: boolean },
): Promise<ToolResult> {
  if (!args?.name) {
    throw new DeplyzeError(ErrorCode.DEPLYZE_E_USAGE, 'A package name is required.');
  }
  const name = args.name.trim();
  assertSafePackageName(name);
  const registry = new RegistryClient({ offline: false });
  const metadata = await registry.getMetadata(name);

  const signal = detectTyposquat({ name });
  const typosquat = signal
    ? {
        similarTo: signal.target,
        distance: signal.distance,
        similarity: signal.similarity,
        confidence: signal.confidence,
        reason: signal.reason,
        recommendedAction: signal.recommendedAction,
      }
    : null;

  const weeklyDownloads =
    args.checkDownloads === false ? undefined : await registry.weeklyDownloads(name).catch(() => undefined);

  if (!metadata) {
    return {
      data: {
        name,
        exists: false,
        typosquat,
        note:
          'The npm registry returned no packument for this name. Either the package does not exist or the registry ' +
          'was unreachable. Deplyze reports "unknown" rather than "safe".',
      },
      text: `${name} could not be resolved on the npm registry (does not exist, or the registry was unreachable).`,
      isError: false,
    };
  }

  const requested = args.version
    ? metadata.versions.find((entry) => entry.version === args.version)
    : undefined;
  const latest = metadata.latest
    ? metadata.versions.find((entry) => entry.version === metadata.latest)
    : undefined;
  const target = requested ?? latest;
  const created = metadata.time?.created;
  const ageDays = created
    ? Math.round((Date.now() - Date.parse(created)) / (1000 * 60 * 60 * 24))
    : undefined;
  const dependencies = Object.keys(target?.dependencies ?? {});

  return {
    data: {
      name,
      exists: true,
      latest: metadata.latest,
      requestedVersion: args.version,
      resolvedVersion: target?.version,
      publishedVersions: metadata.versions.length,
      firstPublished: created,
      ageDays,
      license: target?.license,
      deprecated: target?.deprecated ?? null,
      maintainers: metadata.maintainers?.length ?? 0,
      weeklyDownloads,
      lifecycleScripts: target?.scripts
        ? Object.fromEntries(
            Object.entries(target.scripts).filter(([key]) =>
              ['preinstall', 'install', 'postinstall', 'prepare', 'prepublish', 'prepublishOnly'].includes(
                key,
              ),
            ),
          )
        : {},
      directDependencyCount: dependencies.length,
      directDependencies: dependencies.slice(0, 40),
      repository: metadata.repository,
      typosquat,
      evidence: {
        registryReachable: true,
        typosquatChecked: true,
        downloadsChecked: weeklyDownloads !== undefined,
      },
      verdict:
        'Deplyze does not return a boolean "safe" verdict. Evaluate the evidence above: existence, name similarity, ' +
        'age, maintenance signals, license, lifecycle scripts and dependency footprint.',
    },
    text:
      `${name}${metadata.latest ? `@${metadata.latest}` : ''}: ${metadata.versions.length} published version(s), ` +
      `license ${target?.license ?? 'unknown'}, ${dependencies.length} direct dependencies` +
      (target?.deprecated ? ', DEPRECATED' : '') +
      (typosquat ? `, name-similarity signal vs ${typosquat.similarTo}` : '') +
      '.',
  };
}

export async function toolSbom(
  cache: ScanCache,
  args: { path?: string; format?: SbomFormat },
): Promise<ToolResult> {
  const { result } = await cache.scan(args.path);
  const format = args.format ?? 'cyclonedx';
  return {
    data: {
      format,
      summary: summaryOf(result),
      // The full SBOM is large; agents get a summary plus the invocation hint.
      componentCount: packageCount(result),
      hint: `Run \`deplyze sbom --format ${format}\` to write the full document.`,
    },
    text: `Generated ${format} SBOM summary for ${packageCount(result)} components.`,
  };
}

export async function toolPolicyCheck(cache: ScanCache, args: { path?: string }): Promise<ToolResult> {
  const { result } = await cache.scan(args.path);
  const evaluation = evaluatePolicy(result);
  return {
    data: {
      summary: summaryOf(result),
      passed: evaluation.passed,
      exitCode: evaluation.exitCode,
      violations: evaluation.violations,
      suppressedCount: evaluation.suppressed.length,
      expiredSuppressions: evaluation.expiredSuppressions,
      unusedSuppressions: evaluation.unusedSuppressions,
      policy: {
        failOn: result.config.ci.failOn.length > 0 ? result.config.ci.failOn : result.config.security.failOn,
        deniedLicenses: result.config.licenses.denied,
        deniedPackages: result.config.packages.denied,
        maxCritical: result.config.security.vulnerabilities.maxCritical,
        maxHigh: result.config.security.vulnerabilities.maxHigh,
      },
    },
    text: evaluation.passed
      ? 'Policy check passed.'
      : `Policy check failed with ${evaluation.violations.length} violation(s).`,
  };
}

export async function toolRemediate(cache: ScanCache, args: { path?: string }): Promise<ToolResult> {
  const { result } = await cache.scan(args.path);
  const actionable = result.findings.filter((finding) => finding.remediation);
  const byCategory = new Map<string, number>();
  for (const finding of actionable) {
    byCategory.set(finding.category, (byCategory.get(finding.category) ?? 0) + 1);
  }
  return {
    data: {
      summary: summaryOf(result),
      steps: actionable.map((finding) => ({
        findingId: finding.id,
        severity: finding.severity,
        package: finding.package,
        version: finding.version,
        action: finding.remediation?.summary,
        command: finding.remediation?.command,
        upgrades: finding.remediation?.upgrades,
        steps: finding.remediation?.steps,
      })),
      byCategory: Object.fromEntries(byCategory),
      note: 'Deplyze never modifies manifests or runs package managers. Apply these steps yourself or via your agent.',
    },
    text: `${actionable.length} finding(s) have concrete remediation steps.`,
  };
}

export { summaryOf, findingPayload, generateSbom };
