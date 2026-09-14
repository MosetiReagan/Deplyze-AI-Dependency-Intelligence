import { mkdtemp, rm, mkdir, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { packageNameFromSpecifier, scanSourceUsage, tokenizeCommand } from '../src/index.js';

const dirs: string[] = [];
async function tempDir(): Promise<string> {
  const dir = await mkdtemp(path.join(os.tmpdir(), 'deplyze-src-'));
  dirs.push(dir);
  return dir;
}
afterEach(async () => {
  await Promise.all(dirs.splice(0).map((dir) => rm(dir, { recursive: true, force: true })));
});

describe('packageNameFromSpecifier', () => {
  it('resolves bare and scoped package names', () => {
    expect(packageNameFromSpecifier('lodash')).toBe('lodash');
    expect(packageNameFromSpecifier('lodash/fp')).toBe('lodash');
    expect(packageNameFromSpecifier('@scope/thing/sub')).toBe('@scope/thing');
  });

  it('ignores relative paths, URLs and Node builtins', () => {
    expect(packageNameFromSpecifier('./local.js')).toBeUndefined();
    expect(packageNameFromSpecifier('/abs/path')).toBeUndefined();
    expect(packageNameFromSpecifier('#internal')).toBeUndefined();
    expect(packageNameFromSpecifier('node:fs')).toBeUndefined();
    expect(packageNameFromSpecifier('https://example.com/x.js')).toBeUndefined();
    expect(packageNameFromSpecifier('fs')).toBeUndefined();
    expect(packageNameFromSpecifier('fs/promises')).toBeUndefined();
  });

  it('rejects a malformed scope', () => {
    expect(packageNameFromSpecifier('@scope')).toBeUndefined();
  });
});

describe('tokenizeCommand', () => {
  it('extracts binaries from npm scripts', () => {
    expect(tokenizeCommand('eslint . --fix')).toContain('eslint');
    expect(tokenizeCommand('npx tsc --noEmit')).toContain('tsc');
    expect(tokenizeCommand('pnpm exec vitest run')).toContain('vitest');
    expect(tokenizeCommand('npm run build && rimraf dist')).toContain('rimraf');
  });
});

describe('scanSourceUsage', () => {
  it('indexes imports, requires and script commands', async () => {
    const dir = await tempDir();
    await mkdir(path.join(dir, 'src'), { recursive: true });
    await writeFile(
      path.join(dir, 'package.json'),
      JSON.stringify({ name: 'app', scripts: { build: 'vite build' }, dependencies: { lodash: '^4.0.0' } }),
    );
    await writeFile(
      path.join(dir, 'src', 'index.js'),
      [
        "import lodash from 'lodash';",
        "const minimist = require('minimist');",
        "import('./dynamic.js');",
      ].join('\n'),
    );
    const usage = await scanSourceUsage(dir);
    expect(usage.filesScanned).toBeGreaterThan(0);
    expect(usage.imported.has('lodash')).toBe(true);
    expect(usage.imported.has('minimist')).toBe(true);
    // `import('./dynamic.js')` is a static specifier, so it is *not* dynamic.
    expect(usage.hasDynamicImports).toBe(false);
    expect([...usage.scriptCommands]).toContain('vite');
  });

  it('flags computed dynamic imports', async () => {
    const dir = await tempDir();
    await writeFile(path.join(dir, 'index.js'), 'const name = "x"; import(name);');
    const usage = await scanSourceUsage(dir);
    expect(usage.hasDynamicImports).toBe(true);
  });

  it('bounds the number of files scanned', async () => {
    const dir = await tempDir();
    for (let index = 0; index < 5; index += 1) {
      await writeFile(path.join(dir, `file-${index}.js`), 'export const x = 1;');
    }
    const usage = await scanSourceUsage(dir, { maxFiles: 2 });
    expect(usage.filesScanned).toBeLessThanOrEqual(2);
    expect(usage.truncated).toBe(true);
  });
});
