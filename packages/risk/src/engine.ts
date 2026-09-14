import type {
  CategoryScore,
  Finding,
  GraphStats,
  RiskCategory,
  RiskScore,
  ScoreContribution,
} from '@deplyze/core';

export interface RiskInput {
  findings: Finding[];
  stats: GraphStats;
  /** Direct dependency count, used to normalize small projects. */
  directDependencies: number;
}

interface Rule {
  category: RiskCategory;
  /** Penalty per occurrence. */
  points: number;
  /** Maximum total penalty from this rule within its category. */
  cap: number;
  reason: (count: number) => string;
}

const CATEGORY_WEIGHTS: Record<RiskCategory, number> = {
  security: 0.35,
  'supply-chain': 0.2,
  maintenance: 0.15,
  license: 0.15,
  'dependency-health': 0.1,
  'upgrade-risk': 0.05,
};

const CATEGORY_ORDER: RiskCategory[] = [
  'security',
  'maintenance',
  'supply-chain',
  'license',
  'dependency-health',
  'upgrade-risk',
];

const SEVERITY_PENALTY: Record<string, number> = {
  critical: 40,
  high: 20,
  medium: 8,
  low: 3,
  info: 1,
  unknown: 2,
};

/**
 * Apply a capped, additive penalty per rule.
 *
 * Caps prevent a single noisy signal (for example, forty duplicates in a large
 * monorepo) from saturating a category and hiding other problems. Every
 * deduction produces a human-readable contribution so the score is auditable.
 */
function applyRule(
  contributions: ScoreContribution[],
  rule: Rule,
  count: number,
  evidenceIds: string[] = [],
): void {
  if (count <= 0) return;
  const points = Math.min(count * rule.points, rule.cap);
  contributions.push({
    category: rule.category,
    points: Number(points.toFixed(2)),
    reason: rule.reason(count),
    ...(evidenceIds.length > 0 ? { evidenceIds: evidenceIds.slice(0, 50) } : {}),
  });
}

export function scoreRisk(input: RiskInput): RiskScore {
  const { findings, stats } = input;
  const byCategory = new Map<RiskCategory, Finding[]>();
  for (const finding of findings) {
    const category = mapFindingCategory(finding.category);
    if (!category) continue;
    const list = byCategory.get(category) ?? [];
    list.push(finding);
    byCategory.set(category, list);
  }

  const all: ScoreContribution[] = [];

  // --- Security -----------------------------------------------------------
  const securityContributions: ScoreContribution[] = [];
  for (const severity of ['critical', 'high', 'medium', 'low', 'info'] as const) {
    const matching = (byCategory.get('security') ?? []).filter((f) => f.severity === severity);
    if (matching.length === 0) continue;
    const directBoost = matching.filter((f) => f.paths && f.paths.some((p) => p.length <= 2));
    const weight = SEVERITY_PENALTY[severity] ?? 0;
    const base = matching.length * weight;
    const boost = directBoost.length * weight * 0.25;
    securityContributions.push({
      category: 'security',
      points: Number(Math.min(base + boost, 100).toFixed(2)),
      reason:
        `${matching.length} ${severity} securit${matching.length === 1 ? 'y' : 'ies'} finding${
          matching.length === 1 ? '' : 's'
        }` + (directBoost.length > 0 ? ` (${directBoost.length} directly reachable)` : ''),
      evidenceIds: matching.slice(0, 50).map((f) => f.id),
    });
  }
  applyRule(
    securityContributions,
    {
      category: 'security',
      cap: 12,
      points: 1,
      reason: (count) => `${count} deprecated package${count === 1 ? '' : 's'} marked by the registry`,
    },
    (byCategory.get('maintenance') ?? []).filter((f) => f.title.toLowerCase().includes('deprecated')).length,
  );
  all.push(...securityContributions);

  // --- Maintenance --------------------------------------------------------
  const maintenanceContributions: ScoreContribution[] = [];
  applyRule(
    maintenanceContributions,
    {
      category: 'maintenance',
      points: 10,
      cap: 45,
      reason: (count) => `${count} package${count === 1 ? ' is' : 's are'} deprecated`,
    },
    (byCategory.get('maintenance') ?? []).filter((f) => f.title.toLowerCase().includes('deprecated')).length,
  );
  applyRule(
    maintenanceContributions,
    {
      category: 'maintenance',
      points: 6,
      cap: 30,
      reason: (count) => `${count} package${count === 1 ? ' has' : 's have'} no release in over two years`,
    },
    (byCategory.get('maintenance') ?? []).filter((f) => f.title.toLowerCase().includes('stale')).length,
  );
  all.push(...maintenanceContributions);

  // --- Supply chain -------------------------------------------------------
  const supplyContributions: ScoreContribution[] = [];
  applyRule(
    supplyContributions,
    {
      category: 'supply-chain',
      points: 12,
      cap: 40,
      reason: (count) => `${count} potential typosquatting match${count === 1 ? '' : 'es'}`,
    },
    (byCategory.get('supply-chain') ?? []).filter((f) => f.title.toLowerCase().includes('typosquat')).length,
  );
  applyRule(
    supplyContributions,
    {
      category: 'supply-chain',
      points: 8,
      cap: 32,
      reason: (count) => `${count} package${count === 1 ? '' : 's'} execute lifecycle scripts`,
    },
    (byCategory.get('supply-chain') ?? []).filter((f) => f.title.toLowerCase().includes('lifecycle')).length,
  );
  applyRule(
    supplyContributions,
    {
      category: 'supply-chain',
      points: 10,
      cap: 20,
      reason: (count) => `${count} package${count === 1 ? ' was' : 's were'} published very recently`,
    },
    (byCategory.get('supply-chain') ?? []).filter((f) => f.title.toLowerCase().includes('newly published'))
      .length,
  );
  all.push(...supplyContributions);

  // --- License ------------------------------------------------------------
  const licenseContributions: ScoreContribution[] = [];
  applyRule(
    licenseContributions,
    {
      category: 'license',
      points: 25,
      cap: 75,
      reason: (count) =>
        `${count} license polic${count === 1 ? 'y' : 'ies'} violation${count === 1 ? '' : 's'}`,
    },
    (byCategory.get('license') ?? []).filter((f) => f.severity === 'high' || f.severity === 'critical')
      .length,
  );
  applyRule(
    licenseContributions,
    {
      category: 'license',
      points: 6,
      cap: 24,
      reason: (count) => `${count} package${count === 1 ? '' : 's'} with an unverifiable license`,
    },
    (byCategory.get('license') ?? []).filter((f) => f.severity === 'medium' || f.severity === 'low').length,
  );
  all.push(...licenseContributions);

  // --- Dependency health --------------------------------------------------
  const healthContributions: ScoreContribution[] = [];
  applyRule(
    healthContributions,
    {
      category: 'dependency-health',
      points: 4,
      cap: 30,
      reason: (count) => `${count} package${count === 1 ? '' : 's'} with duplicate versions`,
    },
    stats.duplicateVersions,
  );
  if (stats.maxDepth > 18) {
    healthContributions.push({
      category: 'dependency-health',
      points: 8,
      reason: `Deepest dependency chain is ${stats.maxDepth} levels`,
    });
  }
  if (stats.averageDepth > 6 && stats.totalNodes > 50) {
    healthContributions.push({
      category: 'dependency-health',
      points: 6,
      reason: `Average dependency depth is ${stats.averageDepth} levels`,
    });
  }
  if (stats.totalNodes > 1500) {
    healthContributions.push({
      category: 'dependency-health',
      points: 5,
      reason: `Large transitive footprint (${stats.totalNodes} resolved packages)`,
    });
  }
  all.push(...healthContributions);

  // --- Upgrade risk -------------------------------------------------------
  const upgradeContributions: ScoreContribution[] = [];
  applyRule(
    upgradeContributions,
    {
      category: 'upgrade-risk',
      points: 5,
      cap: 30,
      reason: (count) =>
        `${count} direct dependenc${count === 1 ? 'y is' : 'ies are'} a major version behind`,
    },
    (byCategory.get('upgrade-risk') ?? []).filter((f) => f.title.toLowerCase().includes('major')).length,
  );
  applyRule(
    upgradeContributions,
    {
      category: 'upgrade-risk',
      points: 1.5,
      cap: 12,
      reason: (count) =>
        `${count} direct dependenc${count === 1 ? 'y is' : 'ies are'} a minor version behind`,
    },
    (byCategory.get('upgrade-risk') ?? []).filter((f) => f.title.toLowerCase().includes('minor')).length,
  );
  all.push(...upgradeContributions);

  const categories: CategoryScore[] = CATEGORY_ORDER.map((category) => {
    const contributions = all.filter((c) => c.category === category);
    const penalty = contributions.reduce((sum, c) => sum + c.points, 0);
    return {
      category,
      score: clampScore(100 - penalty),
      contributions,
    };
  });

  const overall = clampScore(
    categories.reduce((sum, category) => sum + category.score * CATEGORY_WEIGHTS[category.category], 0),
  );

  const contributors = [...all].sort((a, b) => b.points - a.points);

  return {
    overall: Number(overall.toFixed(1)),
    band: bandFor(overall),
    categories: categories.map((category) => ({ ...category, score: Number(category.score.toFixed(1)) })),
    contributors,
    methodology:
      'Each category starts at 100. Documented penalties are subtracted per finding with per-rule caps (security 35%, supply chain 20%, maintenance 15%, license 15%, dependency health 10%, upgrade risk 5% weighting). The overall score is the weighted mean of the category scores, so it is a health score: higher is better. Deplyze never fabricates precision the evidence does not support — every point traces to a rule and a finding.',
  };
}

function clampScore(value: number): number {
  if (Number.isNaN(value)) return 100;
  return Math.max(0, Math.min(100, value));
}

function bandFor(score: number): RiskScore['band'] {
  if (score >= 90) return 'excellent';
  if (score >= 75) return 'good';
  if (score >= 55) return 'fair';
  if (score >= 35) return 'poor';
  return 'critical';
}

function mapFindingCategory(category: Finding['category']): RiskCategory | undefined {
  switch (category) {
    case 'vulnerability':
    case 'security':
      return 'security';
    case 'maintenance':
    case 'configuration':
    case 'compatibility':
      return 'maintenance';
    case 'supply-chain':
      return 'supply-chain';
    case 'license':
      return 'license';
    case 'duplicate':
    case 'unused':
      return 'dependency-health';
    case 'outdated':
      return 'upgrade-risk';
    default:
      return undefined;
  }
}
