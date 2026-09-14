import { defineConfig } from 'vitest/config';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const root = path.dirname(fileURLToPath(import.meta.url));
const pkg = (name: string) => path.join(root, 'packages', name, 'src', 'index.ts');

export default defineConfig({
  resolve: {
    alias: {
      // Tests always run against source so a stale `dist` can never mask a
      // regression. The published packages still resolve through ./dist.
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
    include: ['packages/*/test/**/*.test.ts', 'apps/*/test/**/*.test.ts'],
    testTimeout: 20_000,
    hookTimeout: 20_000,
    // Integration tests hit the real OSV/npm APIs and are opt-in.
    exclude: ['**/node_modules/**', '**/dist/**', '**/*.integration.test.ts'],
    reporters: ['default'],
    coverage: {
      provider: 'v8',
      include: ['packages/*/src/**/*.ts', 'apps/cli/src/**/*.ts'],
      exclude: ['**/index.ts', '**/*.d.ts'],
    },
  },
});
