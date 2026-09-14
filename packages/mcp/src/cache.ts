import { resolve } from 'node:path';
import { realpath } from 'node:fs/promises';
import { DeplyzeError, ErrorCode, Logger } from '@deplyze/core';
import { loadConfig, type ResolvedConfig } from '@deplyze/config';
import { runScan, type ScanResult } from '@deplyze/scanners';

/**
 * Shared scan cache.
 *
 * An MCP client typically issues several tool calls in a row for the same
 * project. Re-scanning for each call would be wasteful, so results are memoized
 * per resolved project path for the lifetime of the server process. The cache
 * is keyed on the *real* path so a symlink cannot be used to alias two projects.
 */
export class ScanCache {
  private readonly entries = new Map<string, Promise<ScanResult>>();
  private readonly configEntries = new Map<string, Promise<ResolvedConfig>>();
  private readonly logger: Logger;

  constructor(logger: Logger) {
    this.logger = logger;
  }

  async resolveRoot(input?: string): Promise<string> {
    const candidate = resolve(input && input.length > 0 ? input : process.cwd());
    let resolved: string;
    try {
      resolved = await realpath(candidate);
    } catch {
      throw new DeplyzeError(
        ErrorCode.DEPLYZE_E_PROJECT_NOT_FOUND,
        `Project directory not found: ${input ?? candidate}`,
        {
          hint: 'Pass an absolute path to a directory containing package.json.',
        },
      );
    }
    return resolved;
  }

  async configFor(root: string): Promise<ResolvedConfig> {
    const existing = this.configEntries.get(root);
    if (existing) return existing;
    const promise = loadConfig(root);
    this.configEntries.set(root, promise);
    return promise;
  }

  async scan(rootInput?: string): Promise<{ root: string; result: ScanResult }> {
    const root = await this.resolveRoot(rootInput);
    const existing = this.entries.get(root);
    if (existing) return { root, result: await existing };
    const config = await this.configFor(root);
    const promise = runScan({ root, config, logger: this.logger });
    this.entries.set(root, promise);
    try {
      const result = await promise;
      return { root, result };
    } catch (error) {
      this.entries.delete(root);
      throw error;
    }
  }

  invalidate(rootInput?: string): void {
    if (!rootInput) {
      this.entries.clear();
      this.configEntries.clear();
      return;
    }
    const root = resolve(rootInput);
    this.entries.delete(root);
    this.configEntries.delete(root);
  }
}
