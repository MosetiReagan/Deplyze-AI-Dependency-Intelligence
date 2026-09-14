import { createHash } from 'node:crypto';
import type { DependencyGraph, Finding } from '@deplyze/core';
import type { ScanResult } from '@deplyze/scanners';
import { parseLicenseExpression, collectLicenseIds, normalizeLicenseId } from '@deplyze/scanners';
import { purlFor, sriToHex } from './purl.js';

export interface SbomOptions {
  /** Deterministic serial number (tests, reproducible pipelines). */
  serialNumber?: string;
  timestamp?: string;
  /** Include vulnerability records in the BOM. */
  includeVulnerabilities?: boolean;
  /** Include dependency relationships (defaults to true). */
  includeDependencies?: boolean;
}

/** Deterministic UUIDv5-style serial derived from the project identity. */
function stableSerial(root: string, name: string, version: string | undefined): string {
  const hash = createHash('sha256')
    .update(`${root}|${name}|${version ?? ''}`)
    .digest('hex');
  const uuid = `${hash.slice(0, 8)}-${hash.slice(8, 12)}-5${hash.slice(13, 16)}-a${hash.slice(17, 20)}-${hash.slice(20, 32)}`;
  return `urn:uuid:${uuid}`;
}

function licenseEntries(raw: string | undefined): Array<Record<string, unknown>> | undefined {
  if (!raw) return undefined;
  const parsed = parseLicenseExpression(raw);
  const ids = parsed ? collectLicenseIds(parsed) : [normalizeLicenseId(raw)];
  if (ids.length === 0) return undefined;
  // Deplyze only emits an SPDX `id` when the identifier is a valid SPDX id.
  const spdxLike = /^[A-Za-z0-9.+-]+$/;
  return ids.map((id) => (spdxLike.test(id) ? { license: { id } } : { license: { name: id } }));
}

export function buildCycloneDx(result: ScanResult, options: SbomOptions = {}): Record<string, unknown> {
  const graph: DependencyGraph = result.graph;
  const components: Array<Record<string, unknown>> = [];
  const refs = new Map<string, string>();

  for (const node of graph.nodes()) {
    if (node.depth === 0) continue;
    const ref = purlFor(node);
    refs.set(node.id, ref);
    const component: Record<string, unknown> = {
      type: 'library',
      'bom-ref': ref,
      name: node.name,
      version: node.version,
      scope: node.dev ? 'optional' : 'required',
      purl: ref,
      properties: [
        { name: 'deplyze:ecosystem', value: node.ecosystem },
        { name: 'deplyze:direct', value: String(node.direct) },
        { name: 'deplyze:depth', value: String(node.depth) },
        ...(node.workspace ? [{ name: 'deplyze:workspace', value: node.workspace }] : []),
      ],
    };
    if (node.integrity) {
      const hash = sriToHex(node.integrity);
      if (hash) component.hashes = [{ alg: hash.algorithm, content: hash.hex }];
    }
    const licenses = licenseEntries(node.license);
    if (licenses) component.licenses = licenses;
    if (node.resolved) component.externalReferences = [{ type: 'distribution', url: node.resolved }];
    components.push(component);
  }

  const bom: Record<string, unknown> = {
    bomFormat: 'CycloneDX',
    specVersion: '1.5',
    serialNumber:
      options.serialNumber ?? stableSerial(result.project.root, result.project.name, result.project.version),
    version: 1,
    metadata: {
      timestamp: options.timestamp ?? result.finishedAt,
      tools: [
        {
          vendor: 'Deplyze',
          name: 'deplyze',
          version: '0.1.0',
        },
      ],
      component: {
        type: 'application',
        'bom-ref': `pkg:npm/${encodeURIComponent(result.project.name)}@${result.project.version ?? '0.0.0'}`,
        name: result.project.name,
        version: result.project.version ?? '0.0.0',
        properties: [
          { name: 'deplyze:manager', value: result.project.manager },
          { name: 'deplyze:workspaces', value: String(result.project.workspaces.length) },
        ],
      },
    },
    components,
  };

  if (options.includeDependencies !== false) {
    const dependencies: Array<Record<string, unknown>> = [
      {
        ref: `pkg:npm/${encodeURIComponent(result.project.name)}@${result.project.version ?? '0.0.0'}`,
        dependsOn: graph
          .dependenciesOf('root:.')
          .map((node) => refs.get(node.id))
          .filter((ref): ref is string => !!ref),
      },
    ];
    for (const node of graph.nodes()) {
      if (node.depth === 0) continue;
      const ref = refs.get(node.id);
      if (!ref) continue;
      dependencies.push({
        ref,
        dependsOn: node.dependencies.map((id) => refs.get(id)).filter((value): value is string => !!value),
      });
    }
    bom.dependencies = dependencies;
  }

  if (options.includeVulnerabilities !== false) {
    const vulnerabilities = buildVulnerabilities(result.findings, refs);
    if (vulnerabilities.length > 0) bom.vulnerabilities = vulnerabilities;
  }

  return bom;
}

function buildVulnerabilities(
  findings: Finding[],
  refs: Map<string, string>,
): Array<Record<string, unknown>> {
  const byAdvisory = new Map<string, Finding[]>();
  for (const finding of findings) {
    if (!finding.advisoryId) continue;
    const list = byAdvisory.get(finding.advisoryId) ?? [];
    list.push(finding);
    byAdvisory.set(finding.advisoryId, list);
  }
  const output: Array<Record<string, unknown>> = [];
  for (const [advisoryId, matching] of byAdvisory) {
    const first = matching[0] as Finding;
    const affects = matching
      .map((finding) => {
        const node = [...refs.entries()].find(([, ref]) => ref.startsWith(`pkg:npm/${finding.package}@`));
        return node ? { ref: node[1] } : undefined;
      })
      .filter((entry): entry is { ref: string } => !!entry);
    const ratings: Array<Record<string, unknown>> = [];
    if (first.severity) {
      ratings.push({ severity: first.severity, method: 'other' });
    }
    const entry: Record<string, unknown> = {
      id: advisoryId,
      source: { name: 'OSV' },
      description: first.description,
      ratings,
      affects,
    };
    if (first.references && first.references.length > 0)
      entry.advisories = first.references.map((url) => ({ url }));
    output.push(entry);
  }
  return output;
}
