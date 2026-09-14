/**
 * Core domain types for Deplyze.
 *
 * These types are intentionally ecosystem-neutral: an npm package, a PyPI
 * distribution and a Cargo crate all normalize into the same shapes so that
 * the graph, risk and reporting layers never need ecosystem-specific branches.
 */

/** Package ecosystems Deplyze can reason about. Only `npm` is fully supported today. */
export const ECOSYSTEMS = ['npm', 'pypi', 'cargo', 'go', 'maven', 'nuget', 'composer', 'gem'] as const;

export type Ecosystem = (typeof ECOSYSTEMS)[number];

/** Ecosystems that this release can actually resolve a dependency graph for. */
export const SUPPORTED_ECOSYSTEMS: readonly Ecosystem[] = ['npm'];

export const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info', 'unknown'] as const;
export type Severity = (typeof SEVERITIES)[number];

export const CONFIDENCES = ['high', 'medium', 'low', 'unknown'] as const;
export type Confidence = (typeof CONFIDENCES)[number];

export const FINDING_CATEGORIES = [
  'vulnerability',
  'security',
  'supply-chain',
  'maintenance',
  'license',
  'outdated',
  'unused',
  'duplicate',
  'configuration',
  'compatibility',
] as const;
export type FindingCategory = (typeof FINDING_CATEGORIES)[number];

export const RISK_CATEGORIES = [
  'security',
  'maintenance',
  'supply-chain',
  'license',
  'dependency-health',
  'upgrade-risk',
] as const;
export type RiskCategory = (typeof RISK_CATEGORIES)[number];

/** Dependency kinds, mirroring how package managers classify relationships. */
export type DependencyKind = 'prod' | 'dev' | 'optional' | 'peer';

/** A single resolved node in the dependency graph. */
export interface DependencyNode {
  /** Stable identity: `<ecosystem>:<name>@<version>`. */
  id: string;
  name: string;
  version: string;
  ecosystem: Ecosystem;
  /** Whether a workspace/root manifest declares this dependency directly. */
  direct: boolean;
  /** Declared only in `devDependencies`. */
  dev: boolean;
  /** Declared in `optionalDependencies`, or reached only through optional edges. */
  optional: boolean;
  /** Declared in `peerDependencies`. */
  peer: boolean;
  /**
   * Shortest hop count from a workspace root. `0` is the project itself,
   * direct dependencies are `1`.
   */
  depth: number;
  /** Resolved dependency ids declared by this node. */
  dependencies: string[];
  /** How the dependency was declared, if it is a direct dependency. */
  declaredRange?: string;
  /** Resolved/resolution source recorded by the lockfile (e.g. tarball URL). */
  resolved?: string;
  /** Subresource integrity hash when the lockfile provides one. */
  integrity?: string;
  /** SPDX expression or raw license string, when known from the lockfile. */
  license?: string;
  /** Whether the registry or lockfile marks the package deprecated. */
  deprecated?: boolean;
  /** Lifecycle scripts declared by the package, verbatim (never executed). */
  scripts?: Record<string, string>;
  /** Engine constraints declared by the package. */
  engines?: Record<string, string>;
  /** Reverse index helpers are derived, but cached for convenience. */
  dependents?: string[];
  /** Workspace that declares this node (for monorepos). */
  workspace?: string;
}

/** A named workspace inside a monorepo (or the single root project). */
export interface Workspace {
  /** Directory name relative to the repo root, e.g. `packages/core`. */
  path: string;
  /** `name` field from the workspace manifest, when present. */
  name: string;
  /** `version` field from the workspace manifest, when present. */
  version?: string;
  /** Whether this workspace is private (never published). */
  private: boolean;
  /** Manifest-declared direct dependency names by kind. */
  declared: DependencyDeclaration[];
}

export interface DependencyDeclaration {
  name: string;
  range: string;
  kind: DependencyKind;
  /** Workspace-relative path of the manifest that declared it. */
  manifest: string;
}

/** Normalized view of the project being scanned. */
export interface ProjectModel {
  /** Absolute path of the scanned project root. */
  root: string;
  name: string;
  version?: string;
  private: boolean;
  /** Package manager detected from lockfiles/manifests. */
  manager: 'npm' | 'pnpm' | 'yarn' | 'bun' | 'unknown';
  /** Lockfiles that were discovered and used. */
  lockfiles: LockfileInfo[];
  workspaces: Workspace[];
  nodes: DependencyNode[];
  /** Non-fatal issues encountered while building the model. */
  warnings: ModelWarning[];
}

export interface LockfileInfo {
  /** Workspace-relative path. */
  path: string;
  manager: 'npm' | 'pnpm' | 'yarn' | 'bun';
  /** Format/version string when the lockfile exposes one. */
  formatVersion?: string;
  /** Whether Deplyze parsed the lockfile or fell back to the manifest. */
  parsed: boolean;
  /** Reason parsing failed or was partial. */
  note?: string;
  /** Number of resolved packages the lockfile contributed. */
  resolvedPackages: number;
}

export interface ModelWarning {
  code: string;
  message: string;
  path?: string;
  hint?: string;
}

/** An advisory (vulnerability) record normalized across sources. */
export interface Advisory {
  /** Canonical id, e.g. `GHSA-xxxx-xxxx-xxxx`, `CVE-2024-1234`, `OSV-...`. */
  id: string;
  /** All aliases known for this advisory. */
  aliases: string[];
  package: string;
  ecosystem: Ecosystem;
  /** Affected version ranges as raw strings (OSV/semver ranges). */
  affectedRanges: string[];
  /** Versions explicitly listed as affected. */
  affectedVersions: string[];
  /** Versions that fix the issue. */
  fixedVersions: string[];
  severity?: Severity;
  cvss?: number;
  cvssVector?: string;
  summary: string;
  details?: string;
  references: string[];
  publishedAt?: string;
  modifiedAt?: string;
  /** Where the record came from (e.g. `osv`, `ghsa`, `offline-cache`). */
  source: string;
  /** True when the advisory came from a cached dataset rather than a live call. */
  fromCache?: boolean;
}

export interface Evidence {
  /** Short machine-readable label, e.g. `affected-range`. */
  kind: string;
  /** Human-readable statement of the evidence. */
  message: string;
  /** Optional structured payload (never secrets). */
  data?: Record<string, unknown>;
  /** Optional source URL. */
  url?: string;
}

export interface Remediation {
  summary: string;
  /** Concrete command a developer could run (never executed by Deplyze). */
  command?: string;
  /** Package upgrades that resolve the finding. */
  upgrades?: Array<{ package: string; from: string; to: string; breaking: boolean }>;
  /** Manual steps when automation is unsafe. */
  steps?: string[];
}

export interface Finding {
  id: string;
  category: FindingCategory;
  severity: Severity;
  confidence: Confidence;
  title: string;
  description: string;
  package?: string;
  version?: string;
  ecosystem?: Ecosystem;
  evidence: Evidence[];
  remediation?: Remediation;
  references?: string[];
  /** Scanner that produced the finding, e.g. `security/vulnerability`. */
  source: string;
  /** Advisory id when the finding is backed by an advisory. */
  advisoryId?: string;
  /** Risk weight contribution used by the scoring engine. */
  weight?: number;
  /** Dependency paths that lead to the affected package. */
  paths?: string[][];
}

export interface ScoreContribution {
  category: RiskCategory;
  /** Points added to the risk (positive) or subtracted (negative). */
  points: number;
  reason: string;
  /** Finding/evidence ids that justify the contribution. */
  evidenceIds?: string[];
}

export interface CategoryScore {
  category: RiskCategory;
  /** 0-100 where 100 is the healthiest possible. */
  score: number;
  contributions: ScoreContribution[];
}

export interface RiskScore {
  overall: number;
  band: 'excellent' | 'good' | 'fair' | 'poor' | 'critical';
  categories: CategoryScore[];
  contributors: ScoreContribution[];
  methodology: string;
}

export interface GraphStats {
  totalNodes: number;
  directNodes: number;
  transitiveNodes: number;
  devNodes: number;
  optionalNodes: number;
  maxDepth: number;
  averageDepth: number;
  edgeCount: number;
  duplicateVersions: number;
  packageCountByName: number;
}

export interface ScanSummaryCounts {
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
  unknown: number;
  total: number;
  byCategory: Record<string, number>;
}
