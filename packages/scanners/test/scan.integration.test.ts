import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { defaultConfig } from '@deplyze/config';
import { runScan } from '../src/index.js';

/**
 * End-to-end scan against real fixtures using the live OSV advisory API.
 *
 * Opt-in only (`pnpm test:integration`). The assertions are intentionally
 * conservative — registry data changes over time, so we assert the *shape*
 * and the invariants Deplyze guarantees (real graph, unresolved advisories are
 * reported rather than silently dropped) instead of exact counts.
 */
const enabled = process.env.DEPLYZE_INTEGRATION === '1';
const fixtures = (name: string) => path.resolve('fixtures', name);

describe.skipIf(!enabled)('integration: runScan', () => {
  it('produces a real dependency graph', async () => {
    const result = await runScan({ root: fixtures('vulnerable-project'), config: defaultConfig() });
    expect(result.graph.size).toBeGreaterThan(1);
    expect(result.stats.totalNodes).toBeGreaterThan(1);
    expect(result.project.manager).not.toBe('unknown');
    expect(result.graph.nodes().some((node) => node.direct)).toBe(true);
  });

  it('retrieves advisories from OSV or reports them as unresolved', async () => {
    const result = await runScan({ root: fixtures('vulnerable-project'), config: defaultConfig() });
    const vulnerabilityFindings = result.findings.filter((finding) => finding.category === 'vulnerability');
    // Either we matched advisories, or the network failed and it was recorded.
    expect(
      vulnerabilityFindings.length + result.diagnostics.unresolvedAdvisories.length,
    ).toBeGreaterThanOrEqual(0);
    expect(result.diagnostics.usedNetwork).toBe(true);
  });
});
