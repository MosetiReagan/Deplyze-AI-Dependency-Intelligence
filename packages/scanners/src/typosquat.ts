import type { Finding } from '@deplyze/core';
import { createFinding } from '@deplyze/core';
import { damerauLevenshtein, splitPackageName, similarity } from './levenshtein.js';
import { KNOWN_SIMILAR_NAMES, POPULAR_PACKAGES } from './popular-packages.js';

export interface TyposquatCandidate {
  name: string;
  /** Whether the candidate itself is published on the registry. */
  exists?: boolean;
  /** Weekly downloads, when known. */
  weeklyDownloads?: number;
}

export interface TyposquatSignal {
  name: string;
  target: string;
  distance: number;
  similarity: number;
  reason: string;
  confidence: 'high' | 'medium' | 'low';
  recommendedAction: string;
}

export interface TyposquatOptions {
  maxDistance?: number;
  minNameLength?: number;
  /** Additional names that are considered legitimate. */
  allowlist?: Iterable<string>;
  /** Names to compare against; defaults to the curated popular list. */
  anchors?: readonly string[];
}

/**
 * Compare a package name against the popular-package anchors.
 *
 * Deliberately conservative: Deplyze never asserts malicious intent. It reports
 * a *similarity signal* with a confidence level, and only when
 *   - the name is not itself a known legitimate package, and
 *   - the edit distance is small relative to the name length.
 */
export function detectTyposquat(
  candidate: TyposquatCandidate,
  options: TyposquatOptions = {},
): TyposquatSignal | undefined {
  const maxDistance = options.maxDistance ?? 2;
  const minNameLength = options.minNameLength ?? 5;
  const allowlist = new Set([...KNOWN_SIMILAR_NAMES, ...(options.allowlist ?? [])]);
  const anchors = options.anchors ?? POPULAR_PACKAGES;

  const { base, scope } = splitPackageName(candidate.name);
  if (allowlist.has(candidate.name) || allowlist.has(base)) return undefined;
  if (anchors.includes(candidate.name)) return undefined;
  if (base.length < minNameLength) return undefined;
  // Scoped packages are only suspicious when the *base* mimics an unscoped
  // package, which is the actual scope-confusion attack.
  const effectiveBase = scope ? base : candidate.name;

  let best: TyposquatSignal | undefined;
  for (const anchor of anchors) {
    if (anchor === candidate.name) return undefined;
    if (anchor.startsWith('@')) continue;
    // Anchors come from the curated popular-package list, so they are
    // legitimate by definition. The allowlist only exempts *candidates*.
    if (effectiveBase === anchor) continue;

    const distance = damerauLevenshtein(effectiveBase, anchor, maxDistance);
    if (distance > maxDistance) continue;
    const score = similarity(effectiveBase, anchor);

    // Guard against short names producing spurious matches.
    if (effectiveBase.length <= 4 && distance > 1) continue;
    if (score < 0.8) continue;

    const confidence: TyposquatSignal['confidence'] =
      distance === 1 && score >= 0.9 ? 'high' : distance <= 2 && score >= 0.85 ? 'medium' : 'low';

    if (best && rank(best) >= rank({ confidence } as TyposquatSignal)) continue;
    best = {
      name: candidate.name,
      target: anchor,
      distance,
      similarity: Number(score.toFixed(3)),
      reason:
        distance === 1
          ? `"${effectiveBase}" differs from the popular package "${anchor}" by a single character.`
          : `"${effectiveBase}" is ${distance} edits away from the popular package "${anchor}".`,
      confidence,
      recommendedAction:
        `Verify that "${candidate.name}" is the package you intended to install. ` +
        `Check its repository, publisher and download counts before trusting it. ` +
        `If you meant "${anchor}", install that instead.`,
    };
  }
  return best;
}

function rank(signal: TyposquatSignal): number {
  const confidenceRank = { high: 3, medium: 2, low: 1 } as const;
  return confidenceRank[signal.confidence] * 100 + Math.round(signal.similarity * 100);
}

export function typosquatFindings(signals: TyposquatSignal[]): Finding[] {
  return signals.map((signal) =>
    createFinding({
      category: 'supply-chain',
      severity: signal.confidence === 'high' ? 'high' : signal.confidence === 'medium' ? 'medium' : 'low',
      confidence: signal.confidence,
      title: `Potential typosquat: ${signal.name} resembles ${signal.target}`,
      description:
        `Deplyze detected a package-name similarity signal for "${signal.name}". ` +
        `This is a heuristic, not a verdict: Deplyze has no evidence of malicious intent. ` +
        `Name similarity is one input among several and should be reviewed by a human.`,
      package: signal.name,
      ecosystem: 'npm',
      source: 'supply-chain/typosquat',
      discriminator: `${signal.name}->${signal.target}`,
      evidence: [
        {
          kind: 'similarity',
          message: `Similarity score ${signal.similarity} (edit distance ${signal.distance}) against "${signal.target}".`,
          data: { distance: signal.distance, similarity: signal.similarity, target: signal.target },
        },
      ],
      remediation: {
        summary: signal.recommendedAction,
        steps: [
          `Open the npm page for "${signal.name}" and review the repository and publisher.`,
          `Compare its weekly download count with "${signal.target}".`,
          `If it was added by an AI coding agent, confirm the package exists and was intended.`,
        ],
      },
      references: [`https://www.npmjs.com/package/${encodeURIComponent(signal.name)}`],
    }),
  );
}
