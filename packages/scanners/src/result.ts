import type {
  DependencyGraph,
  Finding,
  GraphStats,
  ProjectModel,
  RiskScore,
  ScanSummaryCounts,
} from '@deplyze/core';
import type { ResolvedConfig } from '@deplyze/config';

export interface ScanDiagnostics {
  /** Scanners that failed, with the reason. Findings from other scanners are kept. */
  scannerErrors: Array<{ scanner: string; message: string }>;
  /** Advisory ids the source could identify but not retrieve. */
  unresolvedAdvisories: string[];
  usedNetwork: boolean;
  usedCache: boolean;
  registryPackagesResolved: number;
  registryPackagesMissing: number;
  /** Registry records served from the local cache instead of the network. */
  registryFromCache: number;
  sourceFilesScanned: number;
  durationMs: number;
  /** Lockfiles that could not be parsed, with the reason. */
  unparsedLockfiles: Array<{ path: string; reason: string }>;
}

export interface ScanResult {
  version: 1;
  project: ProjectModel;
  graph: DependencyGraph;
  findings: Finding[];
  risk: RiskScore;
  summary: ScanSummaryCounts;
  stats: GraphStats;
  diagnostics: ScanDiagnostics;
  config: ResolvedConfig;
  startedAt: string;
  finishedAt: string;
}

/**
 * Number of resolved third-party packages, excluding the workspace root nodes
 * that Deplyze adds to model the project itself.
 */
export function packageCount(result: ScanResult): number {
  return result.stats.totalNodes - result.project.workspaces.length;
}

export function findingById(result: ScanResult, id: string): Finding | undefined {
  return result.findings.find((finding) => finding.id === id);
}
