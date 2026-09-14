import { createFinding, compareVersions, type Finding } from '@deplyze/core';
import { dependencyPaths } from './paths.js';
import type { ScanContext, Scanner } from './types.js';

export const duplicateScanner: Scanner = {
  id: 'graph/duplicates',
  description: 'Finds packages resolved to more than one version.',
  async run(context: ScanContext): Promise<Finding[]> {
    const findings: Finding[] = [];
    const duplicates = context.graph.duplicates();

    for (const [key, nodes] of duplicates) {
      const [, name] = key.split(':');
      const versions = [...new Set(nodes.map((node) => node.version))].sort((a, b) => compareVersions(b, a));
      if (versions.length < 2) continue;

      const distinctMajors = new Set(versions.map((version) => version.split('.')[0])).size;
      const dependents = new Set<string>();
      const paths = [];
      for (const node of nodes) {
        for (const dependent of context.graph.dependentsOf(node.id)) {
          if (dependent.depth > 0) dependents.add(`${dependent.name}@${dependent.version}`);
        }
        for (const path of dependencyPaths(context.graph, node.id, 2))
          paths.push(`${node.version} <- ${path.formatted}`);
      }

      const directVersions = nodes.filter((node) => node.direct).map((node) => node.version);

      findings.push(
        createFinding({
          category: 'duplicate',
          severity: distinctMajors > 1 ? 'medium' : 'low',
          confidence: 'high',
          title: `Duplicate versions of ${name} (${versions.join(', ')})`,
          description:
            `${name} resolves to ${versions.length} versions across the dependency graph. ` +
            (distinctMajors > 1
              ? 'Multiple major versions are present, which usually indicates incompatible dependency ranges.'
              : 'Only one major version is present, so deduplication is usually low-risk.') +
            (directVersions.length > 0
              ? ` Your manifest also declares ${name} at ${directVersions.join(', ')}, so aligning the ranges may resolve it.`
              : ''),
          package: name,
          ecosystem: nodes[0]?.ecosystem ?? 'npm',
          source: 'graph/duplicates',
          stableId: `duplicate|${name}|${versions.join('|')}`,
          evidence: [
            {
              kind: 'versions',
              message: `Resolved versions: ${versions.join(', ')}`,
              data: { versions, distinctMajors },
            },
            {
              kind: 'dependents',
              message:
                dependents.size > 0
                  ? `Packages depending on ${name}: ${[...dependents].slice(0, 10).join(', ')}`
                  : 'No dependents could be attributed.',
              data: { dependents: [...dependents].slice(0, 25) },
            },
            ...paths.slice(0, 5).map((path) => ({ kind: 'dependency-path', message: path })),
          ],
          remediation: {
            summary: `Align ${name} ranges across your manifests, then re-run your package manager's dedupe command.`,
            steps: [
              `Check which direct dependencies require each version of ${name}.`,
              `Raise or lower the declared range so a single version satisfies every dependent.`,
              'Re-run the install with your lockfile updated, then re-scan to confirm.',
            ],
          },
        }),
      );
    }

    return findings;
  },
};
