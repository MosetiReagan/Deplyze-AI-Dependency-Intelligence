import { defineConfig } from 'tsup';

export default defineConfig({
  entry: { bin: 'src/bin.ts', index: 'src/index.ts' },
  format: ['esm'],
  target: 'node20',
  platform: 'node',
  dts: true,
  clean: true,
  sourcemap: true,
  // `src/bin.ts` already carries the `#!/usr/bin/env node` shebang at position
  // zero; esbuild preserves it for the bin entry. Adding a `banner` here would
  // duplicate it and produce an invalid module.
});
