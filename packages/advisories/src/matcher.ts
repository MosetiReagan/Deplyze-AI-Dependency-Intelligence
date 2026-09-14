import { compareVersions, satisfies, type Advisory, type DependencyNode } from '@deplyze/core';

export interface AdvisoryMatch {
  node: DependencyNode;
  advisory: Advisory;
  /** The specific version range or explicit version that matched. */
  matchedOn: string;
  /** Highest fixed version that is greater than the installed version. */
  fixedVersion?: string;
}

export interface MatchOptions {
  /** Consider prerelease versions when matching ranges. Defaults to false. */
  includePrerelease?: boolean;
  /** Skip advisories whose fixed version is older than the installed version. */
  requireApplicableFix?: boolean;
}

/**
 * Test whether an advisory applies to an installed version.
 *
 * Matching uses the advisory's explicit version list first (exact, cheap and
 * unambiguous) and falls back to semver range evaluation. If neither can be
 * evaluated, the advisory is *not* reported as a confirmed match.
 */
export function advisoryAppliesTo(
  advisory: Advisory,
  version: string,
): { applies: boolean; matchedOn?: string; fixedVersion?: string } {
  if (advisory.affectedVersions.includes(version)) {
    const fixedVersion = bestFix(advisory.fixedVersions, version);
    return {
      applies: true,
      matchedOn: `explicit version list (${version})`,
      ...(fixedVersion ? { fixedVersion } : {}),
    };
  }
  for (const range of advisory.affectedRanges) {
    if (satisfies(version, range)) {
      const fixedVersion = bestFix(advisory.fixedVersions, version);
      return { applies: true, matchedOn: range, ...(fixedVersion ? { fixedVersion } : {}) };
    }
  }
  return { applies: false };
}

function bestFix(fixedVersions: string[], version: string): string | undefined {
  const candidates = fixedVersions.filter((fixed) => compareVersions(fixed, version) > 0);
  if (candidates.length === 0) return undefined;
  return candidates.sort((a, b) => compareVersions(a, b))[0];
}

/** Match advisories against graph nodes, only for the ecosystems involved. */
export function matchAdvisories(
  nodes: DependencyNode[],
  advisories: Advisory[],
  options: MatchOptions = {},
): AdvisoryMatch[] {
  const byPackage = new Map<string, Advisory[]>();
  for (const advisory of advisories) {
    const key = `${advisory.ecosystem}:${advisory.package}`;
    const list = byPackage.get(key) ?? [];
    list.push(advisory);
    byPackage.set(key, list);
  }

  const matches: AdvisoryMatch[] = [];
  for (const node of nodes) {
    if (node.depth === 0) continue;
    const candidates = byPackage.get(`${node.ecosystem}:${node.name}`);
    if (!candidates) continue;
    for (const advisory of candidates) {
      const result = advisoryAppliesTo(advisory, node.version);
      if (!result.applies) continue;
      if (options.requireApplicableFix && !result.fixedVersion) {
        // The installed version is already at or beyond every known fix, so the
        // advisory does not describe this installation.
        const anyFixForThisMajor = advisory.fixedVersions.some(
          (fixed) => compareVersions(fixed, node.version) >= 0,
        );
        if (anyFixForThisMajor) continue;
      }
      const match: AdvisoryMatch = {
        node,
        advisory,
        matchedOn: result.matchedOn ?? 'unknown',
      };
      if (result.fixedVersion) match.fixedVersion = result.fixedVersion;
      matches.push(match);
    }
  }
  return matches;
}
