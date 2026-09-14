import semver from 'semver';

export interface RangeMatchResult {
  affected: boolean;
  /** Version that fixes the issue, when the advisory narrows it. */
  fixed?: string;
  reason: string;
}

export function isValidVersion(version: string): boolean {
  return semver.valid(semver.coerce(version) ?? version) !== null || semver.valid(version) !== null;
}

export function parseVersion(version: string): semver.SemVer | null {
  return semver.parse(version, { loose: false }) ?? semver.parse(version, { loose: true });
}

export function compareVersions(a: string, b: string): number {
  const parsedA = parseVersion(a);
  const parsedB = parseVersion(b);
  if (!parsedA || !parsedB) return 0;
  return semver.compare(parsedA, parsedB);
}

export function greaterThan(a: string, b: string): boolean {
  return compareVersions(a, b) > 0;
}

/**
 * Test whether `version` satisfies a range expression.
 *
 * Handles the range syntaxes that appear in OSV/GHSA records:
 *  - plain semver ranges (`>=1.2.3 <1.2.5`)
 *  - `<=`, `<`, `>=`, `>`, `=` prefixes and exact versions
 *  - comma-separated unions
 *  - `*` / `latest`
 *
 * Invalid ranges never match — Deplyze prefers a false negative over a false
 * positive when the source data is malformed.
 */
export function satisfies(version: string, range: string): boolean {
  const trimmed = range.trim();
  if (trimmed === '' || trimmed === '*' || trimmed.toLowerCase() === 'latest') return true;
  const coerced = parseVersion(version);
  if (!coerced) return false;

  // Comma-separated expressions behave as unions in advisory databases.
  if (trimmed.includes(',')) {
    return trimmed.split(',').some((part) => satisfies(version, part.trim()));
  }
  // `||` is standard semver OR.
  try {
    return semver.satisfies(coerced, trimmed, { includePrerelease: false });
  } catch {
    return false;
  }
}

export function isPrerelease(version: string): boolean {
  return parseVersion(version)?.prerelease.length ? true : false;
}

export function majorOf(version: string): number | undefined {
  const parsed = parseVersion(version);
  return parsed?.major;
}

export function minorOf(version: string): number | undefined {
  const parsed = parseVersion(version);
  return parsed?.minor;
}

export function patchOf(version: string): number | undefined {
  const parsed = parseVersion(version);
  return parsed?.patch;
}

export type VersionLag = 'equal' | 'patch' | 'minor' | 'major' | 'downgrade' | 'unknown';

/** Classify how far `current` trails `latest` using semver rules. */
export function classifyLag(current: string, latest: string): VersionLag {
  const a = parseVersion(current);
  const b = parseVersion(latest);
  if (!a || !b) return 'unknown';
  const cmp = semver.compare(a, b);
  if (cmp === 0) return 'equal';
  if (cmp > 0) return 'downgrade';
  if (a.major !== b.major) return 'major';
  if (a.minor !== b.minor) return 'minor';
  return 'patch';
}

/**
 * Highest version in `versions` that satisfies `range` and is newer than
 * `current`, or `undefined`.
 */
export function bestUpgradeWithinRange(
  versions: string[],
  current: string,
  range: string,
): string | undefined {
  const candidates = versions
    .filter((v) => !isPrerelease(v) && satisfies(v, range))
    .filter((v) => compareVersions(v, current) > 0)
    .sort((a, b) => compareVersions(b, a));
  return candidates[0];
}

export function maxVersion(versions: string[]): string | undefined {
  const stable = versions.filter((v) => !isPrerelease(v) && parseVersion(v));
  if (stable.length === 0) return undefined;
  return stable.sort((a, b) => compareVersions(b, a))[0];
}

/** Normalize a declared range (`^1.2.3`, `~1.2`, `1.x`) to a semver range. */
export function normalizeRange(range: string): string | undefined {
  const trimmed = range.trim();
  if (trimmed === '' || trimmed === '*' || trimmed === 'latest') return '*';
  try {
    return semver.validRange(trimmed) ?? undefined;
  } catch {
    return undefined;
  }
}
