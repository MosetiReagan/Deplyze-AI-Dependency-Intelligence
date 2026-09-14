import { createFinding, severityRank, type Advisory, type Evidence, type Finding } from '@deplyze/core';
import type { OsvQuery, AdvisoryMatch } from '@deplyze/advisories';
import { matchAdvisories, OsvClient } from '@deplyze/advisories';
import type { ScanContext, Scanner } from './types.js';
import { dependencyPaths } from './paths.js';

export function advisoryQueriesFor(context: ScanContext): OsvQuery[] {
  const queries: OsvQuery[] = [];
  for (const node of context.graph.allNodes()) {
    if (node.depth === 0) continue;
    if (node.ecosystem !== 'npm') continue;
    queries.push({ name: node.name, version: node.version, ecosystem: node.ecosystem });
  }
  return queries;
}

export function findingsFromMatches(context: ScanContext, matches: AdvisoryMatch[]): Finding[] {
  const findings: Finding[] = [];
  for (const match of matches) {
    const { node, advisory } = match;
    if (context.config.security.vulnerabilities.allowedAdvisories.includes(advisory.id)) continue;
    const paths = dependencyPaths(context.graph, node.id, 3);
    const severity = advisory.severity ?? 'unknown';
    const dependents = context.graph.transitiveDependents(node.id).length;
    const direct = node.direct;

    const evidence: Evidence[] = [
      {
        kind: 'advisory',
        message: `${advisory.id} (${advisory.source}) affects ${advisory.package} on range ${match.matchedOn}.`,
        data: { advisoryId: advisory.id, matchedOn: match.matchedOn, aliases: advisory.aliases },
        url: advisory.references[0],
      },
      {
        kind: 'installed-version',
        message: `Installed version ${node.name}@${node.version} is inside the affected range.`,
      },
      {
        kind: 'reachability',
        message: direct
          ? 'This package is a direct dependency and is therefore directly reachable.'
          : `This package is transitive (depth ${node.depth}) with ${dependents} package(s) depending on it.`,
        data: { depth: node.depth, dependents },
      },
    ];
    if (match.fixedVersion) {
      evidence.push({
        kind: 'fixed-version',
        message: `Version ${match.fixedVersion} or later resolves this advisory.`,
        data: { fixedVersion: match.fixedVersion },
      });
    }
    if (advisory.cvss !== undefined) {
      evidence.push({
        kind: 'cvss',
        message: `CVSS base score ${advisory.cvss}${advisory.cvssVector ? ` (${advisory.cvssVector})` : ''}.`,
        data: { cvss: advisory.cvss, vector: advisory.cvssVector },
      });
    }
    for (const path of paths) {
      evidence.push({
        kind: 'dependency-path',
        message: `Path: ${path.formatted}`,
        data: { path: path.ids, formatted: path.formatted },
      });
    }

    const remediation = buildRemediation(node.name, node.version, match.fixedVersion, advisory);

    findings.push(
      createFinding({
        category: 'vulnerability',
        severity,
        confidence: 'high',
        title: `${advisory.id}: ${advisory.summary}`.slice(0, 200),
        description:
          `${node.name}@${node.version} is affected by ${advisory.id}` +
          (advisory.aliases.length > 0 ? ` (${advisory.aliases.join(', ')})` : '') +
          `. ${advisory.summary}` +
          (direct
            ? ''
            : ` It is pulled in transitively, so updating it may require updating a direct dependency.`),
        package: node.name,
        version: node.version,
        ecosystem: node.ecosystem,
        source: 'security/vulnerability',
        advisoryId: advisory.id,
        stableId: `${advisory.id}|${node.name}|${node.version}`,
        evidence,
        remediation,
        references: advisory.references,
        paths: paths.map((path) => path.ids),
      }),
    );
  }
  return findings;
}

function buildRemediation(
  name: string,
  version: string,
  fixedVersion: string | undefined,
  advisory: Advisory,
): Finding['remediation'] {
  const summary = fixedVersion
    ? `Upgrade ${name} to ${fixedVersion} or later.`
    : `No fixed version is published for ${advisory.id}. Review the advisory and consider an alternative package or a temporary mitigation.`;
  const remediation: NonNullable<Finding['remediation']> = { summary };
  if (fixedVersion) {
    const breaking = fixedVersion.split('.')[0] !== version.split('.')[0];
    remediation.upgrades = [{ package: name, from: version, to: fixedVersion, breaking }];
    remediation.command = `npm install ${name}@${breaking ? fixedVersion : `^${fixedVersion}`}`;
    if (breaking) {
      remediation.steps = [
        `This is a semver-major upgrade of ${name}; review its changelog for breaking changes.`,
        'Re-run your test suite before committing the upgrade.',
      ];
    }
  } else {
    remediation.steps = [
      'Check the advisory references for vendor mitigations.',
      'If the affected package is transitive, find the direct dependency that introduces it and look for a newer release.',
    ];
  }
  return remediation;
}

export const vulnerabilityScanner: Scanner = {
  id: 'security/vulnerability',
  description: 'Matches resolved dependency versions against OSV advisories.',
  async run(context: ScanContext): Promise<Finding[]> {
    if (!context.config.advisories.enabled) return [];
    let advisories: Advisory[];
    if (context.advisoryResult) {
      advisories = context.advisoryResult.advisories;
    } else {
      const client = new OsvClient({
        offline: context.config.scan.offline || !context.config.advisories.allowNetwork,
        cacheDirectory: `${context.config.scan.cache.directory}/advisories`,
        cacheTtlMs: context.config.advisories.ttlHours * 60 * 60 * 1000,
        timeoutMs: context.config.advisories.timeoutMs,
        logger: context.logger,
      });
      const result = await client.queryBatch(advisoryQueriesFor(context));
      context.advisoryResult = result;
      advisories = result.advisories;
    }
    const nodes = [...context.graph.allNodes()].filter((node) => node.depth > 0);
    const matches = matchAdvisories(nodes, advisories, { requireApplicableFix: true });
    const findings = findingsFromMatches(context, matches);
    return findings.sort((a, b) => severityRank(b.severity) - severityRank(a.severity));
  },
};
