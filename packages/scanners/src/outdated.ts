import {
  classifyLag,
  createFinding,
  parseVersion,
  type DependencyNode,
  type Evidence,
  type Finding,
  type VersionLag,
} from '@deplyze/core';
import type { RegistryMetadata } from './registry.js';
import type { ScanContext, Scanner } from './types.js';

export interface OutdatedEntry {
  node: DependencyNode;
  current: string;
  latest: string;
  lag: VersionLag;
  /** Months since the installed version was published, when known. */
  installedAgeMonths?: number;
  /** Months since the latest version was published, when known. */
  latestAgeMonths?: number;
}

const LAG_LABEL: Record<VersionLag, string> = {
  equal: 'Up to date',
  patch: 'Patch behind',
  minor: 'Minor behind',
  major: 'Major behind',
  downgrade: 'Ahead of the registry latest',
  unknown: 'Unknown',
};

export function lagLabel(lag: VersionLag): string {
  return LAG_LABEL[lag];
}

function monthsSince(iso: string | undefined, now: Date): number | undefined {
  if (!iso) return undefined;
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return undefined;
  const months = (now.getTime() - date.getTime()) / (1000 * 60 * 60 * 24 * 30.44);
  return Math.max(0, Number(months.toFixed(1)));
}

export function computeOutdated(
  nodes: DependencyNode[],
  metadata: Map<string, RegistryMetadata>,
  options: { includeDev?: boolean; now?: Date } = {},
): OutdatedEntry[] {
  const now = options.now ?? new Date();
  const entries: OutdatedEntry[] = [];
  for (const node of nodes) {
    if (node.depth === 0) continue;
    if (!options.includeDev && node.dev) continue;
    const meta = metadata.get(node.name);
    if (!meta?.latest) continue;
    const lag = classifyLag(node.version, meta.latest);
    if (lag === 'equal' || lag === 'unknown') continue;
    const entry: OutdatedEntry = { node, current: node.version, latest: meta.latest, lag };
    const installedAgeMonths = monthsSince(meta.time?.[node.version], now);
    if (installedAgeMonths !== undefined) entry.installedAgeMonths = installedAgeMonths;
    const latestAgeMonths = monthsSince(meta.time?.[meta.latest], now);
    if (latestAgeMonths !== undefined) entry.latestAgeMonths = latestAgeMonths;
    entries.push(entry);
  }
  return entries;
}

export const outdatedScanner: Scanner = {
  id: 'outdated/versions',
  description: 'Compares installed versions with registry releases and classifies the version lag.',
  async run(context: ScanContext): Promise<Finding[]> {
    if (!context.config.outdated.enabled) return [];
    const entries = computeOutdated([...context.graph.allNodes()], context.registryMetadata, {
      includeDev: context.config.scan.includeDev,
    });
    const findings: Finding[] = [];

    for (const entry of entries) {
      const { node, lag } = entry;
      const majorChange = parseVersion(node.version)?.major !== parseVersion(entry.latest)?.major;
      const isDirect = node.direct;
      // Transitive drift is reported for majors only: minor drift in a
      // transitive package is normal and not actionable by the developer.
      // (Direct dependencies get findings for every lag kind.)
      if (!isDirect && lag !== 'major') continue;

      const severity = lag === 'major' ? 'medium' : lag === 'minor' ? 'low' : 'info';
      const evidence: Evidence[] = [
        {
          kind: 'version-lag',
          message: `${node.name} is ${lag} behind: installed ${node.version}, latest ${entry.latest}.`,
          data: { current: node.version, latest: entry.latest, lag },
        },
      ];
      if (entry.latestAgeMonths !== undefined) {
        evidence.push({
          kind: 'release-age',
          message: `The latest release (${entry.latest}) is ${entry.latestAgeMonths} months old.`,
          data: { latestAgeMonths: entry.latestAgeMonths },
        });
      }
      if (entry.installedAgeMonths !== undefined) {
        evidence.push({
          kind: 'installed-age',
          message: `The installed version (${node.version}) was published ${entry.installedAgeMonths} months ago.`,
        });
      }
      if (node.declaredRange) {
        evidence.push({
          kind: 'declared-range',
          message: `Your manifest declares ${node.name}@${node.declaredRange}.`,
        });
      }

      const remediation: NonNullable<Finding['remediation']> = {
        summary: `Upgrade ${node.name} from ${node.version} to ${entry.latest}.`,
        command: `npm install ${node.name}@${lag === 'major' ? entry.latest : `^${entry.latest}`}`,
        upgrades: [{ package: node.name, from: node.version, to: entry.latest, breaking: majorChange }],
      };
      if (lag === 'major') {
        remediation.steps = [
          `A major upgrade changes the public API contract. Review the ${node.name} changelog before upgrading.`,
          'Check peer dependency ranges of packages that depend on it.',
          'Run your full test suite after the upgrade.',
        ];
      }

      findings.push(
        createFinding({
          category: 'outdated',
          severity,
          confidence: 'high',
          title: `${lagLabel(lag)}: ${node.name} ${node.version} -> ${entry.latest}`,
          description:
            `${node.name} is ${lag} behind the latest published version ` +
            `(installed ${node.version}, latest ${entry.latest}). ` +
            (lag === 'major'
              ? 'This is a semver-major difference, so breaking changes are possible. Deplyze does not claim the upgrade is safe without evidence.'
              : 'This is a compatible-range difference; review the release notes for behavioural changes.'),
          package: node.name,
          version: node.version,
          ecosystem: node.ecosystem,
          source: 'outdated/versions',
          stableId: `outdated|${node.name}|${node.version}|${entry.latest}`,
          evidence,
          remediation,
        }),
      );
    }
    return findings;
  },
};
