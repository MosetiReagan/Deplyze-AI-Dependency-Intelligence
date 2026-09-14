import { createFinding, type Evidence, type Finding } from '@deplyze/core';
import type { ScanContext, Scanner } from './types.js';

const STALE_MONTHS = 24;

function monthsBetween(fromIso: string | undefined, now: Date): number | undefined {
  if (!fromIso) return undefined;
  const date = new Date(fromIso);
  if (Number.isNaN(date.getTime())) return undefined;
  return Math.max(0, Number(((now.getTime() - date.getTime()) / (1000 * 60 * 60 * 24 * 30.44)).toFixed(1)));
}

export const healthScanner: Scanner = {
  id: 'maintenance/health',
  description: 'Reports deprecated and unmaintained packages with the supporting evidence.',
  async run(context: ScanContext): Promise<Finding[]> {
    const findings: Finding[] = [];
    const now = new Date();

    for (const node of context.graph.allNodes()) {
      if (node.depth === 0) continue;
      const meta = context.registryMetadata.get(node.name);
      const entry = meta?.versions.find((version) => version.version === node.version);
      const deprecationMessage =
        entry?.deprecated ?? (node.deprecated ? 'Marked deprecated in the lockfile.' : undefined);

      if (deprecationMessage) {
        const evidence: Evidence[] = [
          { kind: 'deprecation-notice', message: `Registry deprecation message: ${deprecationMessage}` },
          {
            kind: 'reachability',
            message: node.direct
              ? 'This is a direct dependency.'
              : `This is a transitive dependency at depth ${node.depth}; ${context.graph.transitiveDependents(node.id).length} package(s) depend on it.`,
            data: { depth: node.depth },
          },
        ];
        findings.push(
          createFinding({
            category: 'maintenance',
            severity: node.direct ? 'medium' : 'low',
            confidence: 'high',
            title: `Deprecated package: ${node.name}@${node.version}`,
            description:
              `${node.name}@${node.version} is marked as deprecated by its publisher. ` +
              'A deprecation notice is a direct statement from the maintainer that the package should not be used.',
            package: node.name,
            version: node.version,
            ecosystem: node.ecosystem,
            source: 'maintenance/deprecated',
            stableId: `deprecated|${node.name}|${node.version}`,
            evidence,
            remediation: {
              summary: `Replace ${node.name} with a maintained alternative.`,
              steps: [
                'Read the deprecation notice for the recommended replacement.',
                node.direct
                  ? 'Update your manifest to the replacement package and re-run the test suite.'
                  : 'Identify the direct dependency that introduces it and check for a newer release.',
              ],
            },
          }),
        );
        continue;
      }

      // Staleness is only reported for direct dependencies. A transitive
      // package with no recent release is extremely common and not actionable.
      if (!node.direct || !meta) continue;
      const latestPublished = meta.time?.[meta.latest ?? ''] ?? meta.time?.modified;
      const months = monthsBetween(latestPublished, now);
      if (months === undefined || months < STALE_MONTHS) continue;

      const maintainers = meta.maintainers?.length;
      const evidence: Evidence[] = [
        {
          kind: 'release-age',
          message: `Latest release ${meta.latest ?? node.version} was published ${months} months ago.`,
          data: { months, latest: meta.latest },
        },
        { kind: 'reachability', message: 'This is a direct dependency.' },
      ];
      if (maintainers !== undefined) {
        evidence.splice(1, 0, {
          kind: 'maintainers',
          message: `${maintainers} maintainer(s) are listed for this package.`,
          data: { maintainers },
        });
      }

      findings.push(
        createFinding({
          category: 'maintenance',
          severity: 'low',
          confidence: 'medium',
          title: `Stale release cadence: ${node.name} (${months} months since last release)`,
          description:
            `${node.name} has not published a release in ${months} months. ` +
            'A slow release cadence is not by itself a security problem, and many stable, complete packages are intentionally quiet. ' +
            'Deplyze reports this as a maintenance signal, not a defect.',
          package: node.name,
          version: node.version,
          ecosystem: node.ecosystem,
          source: 'maintenance/stale',
          stableId: `stale|${node.name}|${node.version}`,
          evidence,
          remediation: {
            summary: `Confirm ${node.name} still receives security fixes, or evaluate a maintained alternative.`,
            steps: [
              'Check the repository for recent commits and open issues.',
              'Look for an actively maintained fork or successor package.',
            ],
          },
        }),
      );
    }
    return findings;
  },
};
