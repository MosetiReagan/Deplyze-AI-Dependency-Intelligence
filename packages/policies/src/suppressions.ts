import type { Finding } from '@deplyze/core';
import type { ResolvedConfig, ResolvedSuppression } from '@deplyze/config';

export interface SuppressionMatch {
  finding: Finding;
  suppression: ResolvedSuppression;
}

export interface SuppressionOutcome {
  active: Finding[];
  suppressed: SuppressionMatch[];
  /** Suppressions whose `expires` date has passed. They no longer suppress. */
  expired: ResolvedSuppression[];
  /** Suppressions that matched nothing in this run — stale entries to clean up. */
  unused: ResolvedSuppression[];
}

function isExpired(suppression: ResolvedSuppression, now: Date): boolean {
  if (!suppression.expires) return false;
  const expiry = new Date(suppression.expires);
  if (Number.isNaN(expiry.getTime())) {
    // A malformed expiry must never silently suppress a finding.
    return true;
  }
  return expiry.getTime() <= now.getTime();
}

function matches(suppression: ResolvedSuppression, finding: Finding): boolean {
  if (suppression.package && suppression.package !== finding.package) return false;
  const targets = new Set<string>([finding.id, finding.advisoryId ?? ''].filter(Boolean));
  if (targets.has(suppression.id)) return true;
  // Allow suppressions that use the advisory alias (e.g. a CVE for a GHSA).
  if (finding.references?.some((reference) => reference.includes(suppression.id))) return true;
  return false;
}

/**
 * Apply suppressions from configuration.
 *
 * Expired or malformed suppressions never suppress: a suppression that has
 * lapsed must fail loudly rather than quietly keep a known issue out of CI.
 */
export function applySuppressions(
  findings: Finding[],
  config: ResolvedConfig,
  now: Date = new Date(),
): SuppressionOutcome {
  const expired: ResolvedSuppression[] = [];
  const usable: ResolvedSuppression[] = [];
  for (const suppression of config.ignore) {
    if (isExpired(suppression, now)) expired.push(suppression);
    else usable.push(suppression);
  }

  const matchedIds = new Set<string>();
  const active: Finding[] = [];
  const suppressed: SuppressionMatch[] = [];

  for (const finding of findings) {
    const suppression = usable.find((candidate) => matches(candidate, finding));
    if (suppression) {
      matchedIds.add(suppression.id);
      suppressed.push({ finding, suppression });
    } else {
      active.push(finding);
    }
  }

  const unused = usable.filter((suppression) => !matchedIds.has(suppression.id));
  return { active, suppressed, expired, unused };
}
