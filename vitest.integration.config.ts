import { defineConfig } from 'vitest/config';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const root = path.dirname(fileURLToPath(import.meta.url));
const pkg = (name: string) => path.join(root, 'packages', name, 'src', 'index.ts');

/**
 * Integration project.
 *
 * These tests deliberately call the real OSV and npm registry APIs and are
 * therefore excluded from `pnpm test`. They are opt-in (`pnpm test:integration`)
 * and never run in the default CI job, so a flaky network cannot break a build.
 */
export default defineConfig({
  resolve: {
    alias: {
      '@deplyze/core': pkg('core'),
      '@deplyze/ecosystems': pkg('ecosystems'),
      '@deplyze/advisories': pkg('advisories'),
      '@deplyze/config': pkg('config'),
      '@deplyze/risk': pkg('risk'),
      '@deplyze/scanners': pkg('scanners'),
      '@deplyze/sbom': pkg('sbom'),
      '@deplyze/reporters': pkg('reporters'),
      '@deplyze/policies': pkg('policies'),
      '@deplyze/ai': pkg('ai'),
      '@deplyze/mcp': pkg('mcp'),
    },
  },
  test: {
    environment: 'node',
    include: ['packages/*/test/**/*.integration.test.ts', 'apps/*/test/**/*.integration.test.ts'],
    testTimeout: 60_000,
    hookTimeout: 60_000,
    reporters: ['default'],
  },
});
