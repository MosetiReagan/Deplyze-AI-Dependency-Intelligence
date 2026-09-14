/**
 * CVSS v3.0/v3.1 base score calculation.
 *
 * Advisory databases (OSV, GHSA, NVD) commonly publish a CVSS *vector* rather
 * than a numeric score. Deplyze computes the base score itself using the
 * published FIRST specification rather than guessing a severity, so every
 * number in a report traces back to a deterministic formula.
 *
 * CVSS v4 vectors are recorded but not scored — Deplyze reports the vector and
 * marks the numeric score as unknown rather than approximating.
 */

export interface CvssResult {
  score: number;
  vector: string;
  version: '3.0' | '3.1';
}

const AV: Record<string, number> = { N: 0.85, A: 0.62, L: 0.55, P: 0.2 };
const AC: Record<string, number> = { L: 0.77, H: 0.44 };
const PR_UNCHANGED: Record<string, number> = { N: 0.85, L: 0.62, H: 0.27 };
const PR_CHANGED: Record<string, number> = { N: 0.85, L: 0.68, H: 0.5 };
const UI: Record<string, number> = { N: 0.85, R: 0.62 };
const CIA: Record<string, number> = { H: 0.56, L: 0.22, N: 0 };

function roundUp(value: number): number {
  const scaled = Math.round(value * 100000);
  if (Math.abs(value * 100000 - scaled) < 1e-9) return scaled / 100000;
  return Math.ceil(value * 100000) / 100000;
}

export function parseCvssVector(vector: string): Record<string, string> | undefined {
  const match = vector.trim().match(/^CVSS:(3\.[01])\/(.+)$/i);
  if (!match) return undefined;
  const metrics: Record<string, string> = {};
  for (const part of (match[2] ?? '').split('/')) {
    const [key, value] = part.split(':');
    if (key && value) metrics[key.toUpperCase()] = value.toUpperCase();
  }
  return metrics;
}

export function scoreCvssVector(vector: string): CvssResult | undefined {
  const match = vector.trim().match(/^CVSS:(3\.[01])\//i);
  if (!match) return undefined;
  const metrics = parseCvssVector(vector);
  if (!metrics) return undefined;
  const scopeChanged = metrics.S === 'C';

  const av = AV[metrics.AV ?? ''];
  const ac = AC[metrics.AC ?? ''];
  const pr = (scopeChanged ? PR_CHANGED : PR_UNCHANGED)[metrics.PR ?? ''];
  const ui = UI[metrics.UI ?? ''];
  const c = CIA[metrics.C ?? ''];
  const i = CIA[metrics.I ?? ''];
  const a = CIA[metrics.A ?? ''];

  if ([av, ac, pr, ui, c, i, a].some((value) => value === undefined)) return undefined;
  if (!metrics.AV || !metrics.AC || !metrics.PR || !metrics.UI || !metrics.C || !metrics.I || !metrics.A) {
    return undefined;
  }

  const iss = 1 - (1 - (c as number)) * (1 - (i as number)) * (1 - (a as number));
  const impact = scopeChanged ? 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15) : 6.42 * iss;
  if (impact <= 0) {
    return { score: 0, vector, version: (match[1] as string) === '3.0' ? '3.0' : '3.1' };
  }
  const exploitability = 8.22 * (av as number) * (ac as number) * (pr as number) * (ui as number);
  const raw = scopeChanged
    ? Math.min(1.08 * (impact + exploitability), 10)
    : Math.min(impact + exploitability, 10);
  const score = Math.ceil(roundUp(raw) * 10) / 10;
  return {
    score: Number(score.toFixed(1)),
    vector,
    version: (match[1] as string) === '3.0' ? '3.0' : '3.1',
  };
}

/** Map a numeric CVSS score to the qualitative rating used across Deplyze. */
export function severityFromCvss(score: number): 'critical' | 'high' | 'medium' | 'low' | 'info' {
  if (score >= 9) return 'critical';
  if (score >= 7) return 'high';
  if (score >= 4) return 'medium';
  if (score > 0) return 'low';
  return 'info';
}
