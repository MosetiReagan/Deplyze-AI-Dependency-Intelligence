import {
  createFinding,
  type DependencyNode,
  type Evidence,
  type Finding,
  type ProjectModel,
} from '@deplyze/core';
import type { RegistryMetadata } from './registry.js';
import type { ScanContext, Scanner } from './types.js';
import {
  collectLicenseIds,
  copyleftFamily,
  evaluateLicenseExpression,
  isUnknownLicense,
  normalizeLicenseId,
  parseLicenseExpression,
} from './license-expression.js';

export interface ResolvedLicense {
  /** Raw declared licence string, exactly as published. */
  raw?: string;
  /** Normalized primary identifier, when one could be derived. */
  id?: string;
  /** All identifiers mentioned by the expression. */
  ids: string[];
  /** Where the licence came from. */
  source: 'lockfile' | 'registry' | 'unknown';
}

/** Resolve the licence for a package version, preferring lockfile data. */
export function resolveLicense(
  node: DependencyNode,
  metadata: RegistryMetadata | undefined,
): ResolvedLicense {
  let raw = node.license;
  let source: ResolvedLicense['source'] = raw ? 'lockfile' : 'unknown';
  if (!raw && metadata) {
    const entry = metadata.versions.find((version) => version.version === node.version);
    const candidate = entry?.license ?? metadata.versions.find((v) => v.version === metadata.latest)?.license;
    if (candidate) {
      raw = candidate;
      source = 'registry';
    }
  }
  if (!raw || isUnknownLicense(raw)) {
    return { ids: [], source: 'unknown' };
  }
  const parsed = parseLicenseExpression(raw);
  const ids = parsed ? collectLicenseIds(parsed) : [normalizeLicenseId(raw)];
  const result: ResolvedLicense = { raw, ids, source };
  if (ids.length > 0) result.id = ids[0];
  return result;
}

export function licenseFindingsFor(
  nodes: DependencyNode[],
  metadata: Map<string, RegistryMetadata>,
  project: ProjectModel,
  policy: {
    allowed: string[];
    denied: string[];
    unknown: 'ignore' | 'warn' | 'fail';
    failOnDenied: boolean;
  },
): Finding[] {
  const allowedSet = new Set(policy.allowed.map((entry) => normalizeLicenseId(entry)));
  const deniedSet = new Set(policy.denied.map((entry) => normalizeLicenseId(entry)));
  const findings: Finding[] = [];

  for (const node of nodes) {
    const license = resolveLicense(node, metadata.get(node.name));
    const declared = license.raw;

    if (license.source === 'unknown' || license.ids.length === 0) {
      if (policy.unknown === 'ignore') continue;
      findings.push(
        createFinding({
          category: 'license',
          severity: policy.unknown === 'fail' ? 'high' : 'low',
          confidence: 'medium',
          title: `Unknown license: ${node.name}@${node.version}`,
          description:
            `Deplyze could not determine a license for ${node.name}@${node.version}. ` +
            'An unknown license is not the same as a permissive license: review the package before relying on it.',
          package: node.name,
          version: node.version,
          ecosystem: node.ecosystem,
          source: 'license/unknown',
          stableId: `license-unknown|${node.name}|${node.version}`,
          evidence: [
            {
              kind: 'license-source',
              message:
                license.source === 'unknown'
                  ? 'No license field was found in the lockfile or registry metadata.'
                  : `Declared license "${declared}" could not be interpreted.`,
            },
          ],
          remediation: {
            summary: `Check the package repository for a LICENSE file, or choose a dependency with a declared license.`,
            steps: [
              `Open https://www.npmjs.com/package/${node.name} and inspect the license field.`,
              'If the package is unlicensed, treat it as all-rights-reserved and seek legal guidance.',
            ],
          },
        }),
      );
      continue;
    }

    const parsed = declared ? parseLicenseExpression(declared) : undefined;
    const isAcceptable = (id: string): boolean => {
      const normalized = normalizeLicenseId(id);
      if (deniedSet.has(normalized)) return false;
      if (allowedSet.size === 0) return true;
      return allowedSet.has(normalized);
    };

    const evaluation = parsed
      ? evaluateLicenseExpression(parsed, isAcceptable)
      : {
          acceptable: license.ids.every(isAcceptable),
          reason: '',
          rejected: license.ids.filter((id) => !isAcceptable(id)),
        };
    if (evaluation.acceptable) continue;

    const rejected = evaluation.rejected.length > 0 ? evaluation.rejected : license.ids;
    const denied = rejected.filter((id) => deniedSet.has(normalizeLicenseId(id)));
    const copyleft = rejected.map((id) => copyleftFamily(id)).find(Boolean);
    const severity = policy.failOnDenied ? (denied.length > 0 ? 'high' : 'medium') : 'low';

    const evidence: Evidence[] = [
      {
        kind: 'license',
        message: `Declared license: ${declared}`,
        data: { raw: declared, ids: license.ids, source: license.source },
      },
      {
        kind: 'policy',
        message: evaluation.reason || `Rejected identifiers: ${rejected.join(', ')}`,
        data: {
          denied: policy.denied,
          allowed: policy.allowed,
        },
      },
    ];
    if (copyleft) {
      evidence.push({
        kind: 'copyleft',
        message: `This is a ${copyleft} copyleft license. Distributing the package may impose obligations on your own code.`,
        data: { family: copyleft },
      });
    }

    findings.push(
      createFinding({
        category: 'license',
        severity,
        confidence: 'high',
        title: `License policy violation: ${node.name}@${node.version} uses ${rejected.join(', ')}`,
        description:
          `${node.name}@${node.version} declares the license "${declared}", which the configured policy does not permit.` +
          (copyleft ? ` The license is ${copyleft} copyleft.` : '') +
          ' Deplyze does not provide legal advice; treat this as a prompt for review.',
        package: node.name,
        version: node.version,
        ecosystem: node.ecosystem,
        source: 'license/policy',
        stableId: `license-policy|${node.name}|${node.version}|${declared}`,
        evidence,
        remediation: {
          summary: `Review whether "${declared}" is acceptable for your distribution model, or replace ${node.name}.`,
          steps: [
            'Confirm the obligation the license imposes on your distribution model.',
            'Check whether an alternative package or a commercial license is available.',
            `If the dependency is transitive, identify the direct dependency that introduces it (see the dependency path in deplyze graph).`,
          ],
        },
        references: [`https://spdx.org/licenses/`],
      }),
    );
  }

  void project;
  return findings;
}

export const licenseScanner: Scanner = {
  id: 'license/policy',
  description: 'Evaluates declared licenses against the configured allow/deny policy.',
  async run(context: ScanContext): Promise<Finding[]> {
    const nodes = [...context.graph.allNodes()].filter((node) => node.depth > 0);
    return licenseFindingsFor(nodes, context.registryMetadata, context.project, {
      allowed: context.config.licenses.allowed,
      denied: context.config.licenses.denied,
      unknown: context.config.licenses.unknown,
      failOnDenied: context.config.licenses.failOnDenied,
    });
  },
};
