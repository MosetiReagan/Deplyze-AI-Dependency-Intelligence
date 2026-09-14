import { Logger, dedupeFindings, summarize, type DependencyNode } from '@deplyze/core';
import type { ResolvedConfig } from '@deplyze/config';
import { loadProject, type LoadOptions } from '@deplyze/ecosystems';
import { OsvClient } from '@deplyze/advisories';
import { scoreRisk } from '@deplyze/risk';
import { RegistryClient, type RegistryMetadata } from './registry.js';
import { scanSourceUsage } from './source-usage.js';
import { vulnerabilityScanner, advisoryQueriesFor } from './vulnerabilities.js';
import { licenseScanner } from './licenses.js';
import { duplicateScanner } from './duplicates.js';
import { outdatedScanner } from './outdated.js';
import { healthScanner } from './health.js';
import { lifecycleScanner } from './lifecycle.js';
import { unusedScanner } from './unused.js';
import { supplyChainScanner } from './supply-chain.js';
import type { ScanContext } from './types.js';
import type { ScanResult } from './result.js';
import { ScannerRegistry } from './types.js';

export interface ScanOptions {
  root: string;
  config: ResolvedConfig;
  logger?: Logger;
  /** Restrict to a subset of scanners (ids). */
  only?: string[];
  signal?: AbortSignal;
}

export function defaultScanners(): ScannerRegistry {
  return new ScannerRegistry()
    .register(vulnerabilityScanner)
    .register(licenseScanner)
    .register(duplicateScanner)
    .register(outdatedScanner)
    .register(healthScanner)
    .register(lifecycleScanner)
    .register(supplyChainScanner)
    .register(unusedScanner);
}

/**
 * Prefetch registry metadata for the packages the scanners need.
 *
 * Direct dependencies are always fetched (outdated, lifecycle, unused-bin
 * evidence). Packages whose license is not recorded in the lockfile are added
 * so the license scanner can resolve them. The set is capped by configuration
 * so a huge transitive graph cannot generate unbounded network traffic.
 */
function packagesNeedingMetadata(
  nodes: DependencyNode[],
  config: ResolvedConfig,
  options: { includeLicense?: boolean } = {},
): { needed: string[]; truncated: boolean } {
  const direct = new Set<string>();
  const licenseUnknown = new Set<string>();
  for (const node of nodes) {
    if (node.depth === 0) continue;
    if (node.direct) direct.add(node.name);
    if (options.includeLicense !== false && !node.license) licenseUnknown.add(node.name);
    if (node.deprecated) licenseUnknown.add(node.name);
  }
  const ordered = [...direct, ...[...licenseUnknown].filter((name) => !direct.has(name))];
  const limit = config.scan.registry.maxPackages;
  return { needed: ordered.slice(0, limit), truncated: ordered.length > limit };
}

export async function runScan(options: ScanOptions): Promise<ScanResult> {
  const logger = options.logger ?? new Logger({ level: 'silent' });
  const config = options.config;
  const startedAt = new Date();
  const cacheDirectory = config.scan.cache.directory;

  const loadOptions: LoadOptions = { logger };
  if (options.root) loadOptions.forceManager = undefined;
  const loaded = await loadProject(options.root, loadOptions);
  const { project, graph } = loaded;

  const registry = new RegistryClient({
    enabled: config.scan.registry.enabled,
    baseUrl: config.scan.registry.url,
    timeoutMs: config.scan.registry.timeoutMs,
    concurrency: config.scan.registry.concurrency,
    cacheDirectory: `${cacheDirectory}/registry`,
    cacheTtlMs: config.scan.cache.ttlHours * 60 * 60 * 1000,
    offline: config.scan.offline,
    logger,
  });

  const advisories = new OsvClient({
    offline: config.scan.offline || !config.advisories.allowNetwork,
    cacheDirectory: `${cacheDirectory}/advisories`,
    cacheTtlMs: config.advisories.ttlHours * 60 * 60 * 1000,
    timeoutMs: config.advisories.timeoutMs,
    logger,
  });

  const nodes = graph.nodes();
  const includeLicense =
    config.licenses.denied.length > 0 ||
    config.licenses.allowed.length > 0 ||
    config.licenses.unknown !== 'ignore' ||
    config.licenses.failOnDenied;
  const { needed, truncated } = packagesNeedingMetadata(nodes, config, { includeLicense });
  if (truncated) {
    logger.warn(
      `Registry metadata lookup capped at ${config.scan.registry.maxPackages} packages; some findings may be unavailable.`,
    );
  }

  let registryMetadata = new Map<string, RegistryMetadata>();
  if ((config.scan.registry.enabled || config.scan.offline) && needed.length > 0) {
    registryMetadata = await registry.metadataFor(needed);
  }
  let registryFromCache = 0;
  for (const meta of registryMetadata.values()) if (meta.fromCache) registryFromCache += 1;

  // Backfill licenses discovered in the registry into the graph so every
  // downstream consumer (SBOM, reports, JSON output) sees the same data the
  // license scanner evaluated.
  backfillLicenses(nodes, registryMetadata);

  const context: ScanContext = {
    root: options.root,
    project,
    graph,
    config,
    registry,
    advisories,
    logger,
    registryMetadata,
  };
  if (options.signal) context.signal = options.signal;

  // Advisory lookup happens once and is shared with the vulnerability scanner.
  if (config.advisories.enabled) {
    try {
      context.advisoryResult = await advisories.queryBatch(advisoryQueriesFor(context));
    } catch (error) {
      logger.warn('Advisory lookup failed; vulnerability findings will be unavailable.', {
        error: String(error),
      });
    }
  }

  if (config.unused.enabled) {
    context.sourceUsage = await scanSourceUsage(options.root, {
      exclude: config.scan.exclude,
      ...(options.signal ? { signal: options.signal } : {}),
    });
  }

  const registryIds = options.only ? new Set(options.only) : undefined;
  const scanners = defaultScanners()
    .all()
    .filter((scanner) => !registryIds || registryIds.has(scanner.id));

  const scannerErrors: ScanResult['diagnostics']['scannerErrors'] = [];
  const findingGroups = await Promise.all(
    scanners.map(async (scanner) => {
      try {
        return await scanner.run(context);
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        logger.warn(`Scanner ${scanner.id} failed`, { error: message });
        scannerErrors.push({ scanner: scanner.id, message });
        return [];
      }
    }),
  );

  const findings = dedupeFindings(findingGroups.flat());
  const stats = graph.stats();
  const risk = scoreRisk({
    findings,
    stats,
    directDependencies: stats.directNodes,
  });

  const finishedAt = new Date();
  const registryPackagesMissing = needed.filter((name) => !registryMetadata.has(name)).length;
  const registryNetworkUsed = registryMetadata.size > registryFromCache;
  const advisoryNetworkUsed = config.advisories.enabled && !config.scan.offline && !!context.advisoryResult;
  const networkUsed = registryNetworkUsed || advisoryNetworkUsed;
  const cacheUsed = registryFromCache > 0 || (context.advisoryResult?.usedCache ?? false);

  return {
    version: 1,
    project,
    graph,
    findings,
    risk,
    summary: summarize(findings),
    stats,
    diagnostics: {
      scannerErrors,
      registryFromCache,
      unresolvedAdvisories: context.advisoryResult?.unresolved ?? [],
      usedNetwork: networkUsed,
      usedCache: cacheUsed,
      registryPackagesResolved: registryMetadata.size,
      registryPackagesMissing,
      sourceFilesScanned: context.sourceUsage?.filesScanned ?? 0,
      durationMs: finishedAt.getTime() - startedAt.getTime(),
      unparsedLockfiles: project.lockfiles
        .filter((lockfile) => !lockfile.parsed)
        .map((lockfile) => ({
          path: lockfile.path,
          reason: lockfile.note ?? 'Unsupported lockfile format.',
        })),
    },
    config,
    startedAt: startedAt.toISOString(),
    finishedAt: finishedAt.toISOString(),
  };
}

/**
 * Copy registry-resolved licenses onto graph nodes that the lockfile did not
 * annotate. Without this, an SBOM generated from the same scan would report
 * `NOASSERTION` for packages whose license Deplyze actually verified.
 */
function backfillLicenses(nodes: DependencyNode[], metadata: Map<string, RegistryMetadata>): void {
  for (const node of nodes) {
    if (node.license || node.depth === 0) continue;
    const entry = metadata.get(node.name)?.versions.find((version) => version.version === node.version);
    if (entry?.license) node.license = entry.license;
  }
}
