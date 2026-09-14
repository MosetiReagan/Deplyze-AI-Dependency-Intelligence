import type { DependencyGraph, Finding, Logger, ProjectModel } from '@deplyze/core';
import type { ResolvedConfig } from '@deplyze/config';
import type { OsvClient, AdvisoryQueryResult } from '@deplyze/advisories';
import type { RegistryClient, RegistryMetadata } from './registry.js';
import type { SourceUsage } from './source-usage.js';

export interface ScanContext {
  root: string;
  project: ProjectModel;
  graph: DependencyGraph;
  config: ResolvedConfig;
  registry: RegistryClient;
  advisories: OsvClient;
  logger: Logger;
  /** Prefetched registry metadata for the packages the scanners need. */
  registryMetadata: Map<string, RegistryMetadata>;
  /** Result of the advisory lookup, when the vulnerability scanner ran. */
  advisoryResult?: AdvisoryQueryResult;
  /** Source-file usage index, when the unused-dependency scanner ran. */
  sourceUsage?: SourceUsage;
  signal?: AbortSignal;
}

export interface Scanner {
  /** Stable scanner id used in finding `source` fields and diagnostics. */
  id: string;
  /** Short human description used by `deplyze doctor`. */
  description: string;
  run(context: ScanContext): Promise<Finding[]>;
}

export class ScannerRegistry {
  private readonly scanners: Scanner[] = [];

  register(scanner: Scanner): this {
    this.scanners.push(scanner);
    return this;
  }

  all(): Scanner[] {
    return [...this.scanners];
  }

  byId(id: string): Scanner | undefined {
    return this.scanners.find((scanner) => scanner.id === id);
  }
}
