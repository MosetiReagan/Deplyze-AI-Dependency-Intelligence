import { createFinding, type Finding } from '@deplyze/core';
import type { ScanContext, Scanner } from './types.js';
import { detectTyposquat, typosquatFindings } from './typosquat.js';
import type { RegistryMetadata } from './registry.js';

const NEW_PACKAGE_DAYS = 30;

export const supplyChainScanner: Scanner = {
  id: 'supply-chain/typosquat',
  description: 'Reports name-similarity signals and recently published direct dependencies.',
  async run(context: ScanContext): Promise<Finding[]> {
    const findings: Finding[] = [];
    const typosquatConfig = context.config.supplyChain.typosquat;

    if (typosquatConfig.enabled) {
      const signals = [];
      for (const node of context.graph.allNodes()) {
        if (!node.direct || node.depth === 0) continue;
        if (context.config.packages.allowed.includes(node.name)) continue;
        if (context.config.supplyChain.allowlist.includes(node.name)) continue;
        const signal = detectTyposquat(
          { name: node.name },
          {
            maxDistance: typosquatConfig.maxDistance,
            minNameLength: typosquatConfig.minNameLength,
            allowlist: context.config.supplyChain.allowlist,
          },
        );
        if (signal) signals.push(signal);
      }
      findings.push(...typosquatFindings(signals));
    }

    // Recently published packages are a real supply-chain signal: a brand-new
    // dependency is far more likely to be an AI-hallucinated or hijacked name.
    const now = Date.now();
    for (const node of context.graph.allNodes()) {
      if (!node.direct || node.depth === 0) continue;
      const meta = context.registryMetadata.get(node.name);
      if (!meta) continue;
      const created = meta.time?.created;
      if (!created) continue;
      const createdTime = Date.parse(created);
      if (Number.isNaN(createdTime)) continue;
      const ageDays = (now - createdTime) / (1000 * 60 * 60 * 24);
      if (ageDays > NEW_PACKAGE_DAYS) continue;

      findings.push(
        createFinding({
          category: 'supply-chain',
          severity: 'medium',
          confidence: 'high',
          title: `Newly published dependency: ${node.name} (${Math.round(ageDays)} days old)`,
          description:
            `${node.name} first appeared in the npm registry ${Math.round(ageDays)} day(s) ago. ` +
            'New package names are a common vector for typosquatting and for packages invented by AI coding agents. ' +
            'Age alone does not make a package unsafe, but it removes the community review that older packages have had.',
          package: node.name,
          version: node.version,
          ecosystem: node.ecosystem,
          source: 'supply-chain/new-package',
          stableId: `new-package|${node.name}|${created}`,
          evidence: [
            {
              kind: 'publish-age',
              message: `First published ${created} (${Math.round(ageDays)} days ago).`,
              data: { created, ageDays: Math.round(ageDays) },
            },
            {
              kind: 'availability',
              message: `Registry reports ${meta.versions.length} published version(s).`,
              data: { versions: meta.versions.length },
            },
          ],
          remediation: {
            summary: `Confirm ${node.name} is the package you intended before relying on it.`,
            steps: [
              'Open the package repository and verify the publisher and source code.',
              'Check whether an established alternative exists.',
            ],
          },
          references: [`https://www.npmjs.com/package/${node.name}`],
        }),
      );
    }

    return findings;
  },
};

/** Exposed for the pre-install guard and `deplyze package`. */
export interface PackageRiskInput {
  name: string;
  version?: string;
  metadata?: RegistryMetadata;
  allowlist?: string[];
}

export const __internals = { NEW_PACKAGE_DAYS };
