import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { DeplyzeError, ErrorCode } from '@deplyze/core';
import { defaultConfig, loadConfig, loadConfigFile, resolveConfig } from '../src/index.js';

const tempDirs: string[] = [];

async function tempDir(): Promise<string> {
  const dir = await mkdtemp(path.join(os.tmpdir(), 'deplyze-config-'));
  tempDirs.push(dir);
  return dir;
}

afterEach(async () => {
  await Promise.all(tempDirs.splice(0).map((dir) => rm(dir, { recursive: true, force: true })));
});

describe('resolveConfig', () => {
  it('applies documented defaults', () => {
    const config = resolveConfig({});
    expect(config.version).toBe(1);
    expect(config.security.failOn).toEqual(['critical', 'high']);
    expect(config.licenses.unknown).toBe('warn');
    expect(config.ai.enabled).toBe(false);
    expect(config.ai.provider).toBe('none');
    expect(config.scan.ecosystems).toEqual(['npm']);
  });

  it('parses a realistic configuration', () => {
    const config = resolveConfig({
      version: 1,
      scan: { ecosystems: ['npm'] },
      security: { failOn: ['critical'] },
      licenses: { denied: ['AGPL-3.0'] },
      packages: { denied: ['suspicious-package'] },
      ignore: [{ id: 'GHSA-xxxx', reason: 'Accepted temporarily', expires: '2027-01-01' }],
    });
    expect(config.security.failOn).toEqual(['critical']);
    expect(config.licenses.denied).toEqual(['AGPL-3.0']);
    expect(config.packages.denied).toEqual(['suspicious-package']);
    expect(config.ignore).toHaveLength(1);
    expect(config.ignore[0]?.expires).toBe('2027-01-01');
  });

  it('warns about unknown top-level keys instead of silently ignoring them', () => {
    const config = resolveConfig({ secuirty: { failOn: ['critical'] } });
    expect(config.warnings.map((warning) => warning.code)).toContain('config.unknown-key');
  });

  it('rejects structurally invalid configuration with an actionable error', () => {
    try {
      resolveConfig({ ignore: [{ id: 'x' }] });
      throw new Error('expected resolveConfig to throw');
    } catch (error) {
      expect(error).toBeInstanceOf(DeplyzeError);
      expect((error as DeplyzeError).code).toBe(ErrorCode.DEPLYZE_E_CONFIG);
    }
  });

  it('requires a reason for every suppression', () => {
    expect(() => resolveConfig({ ignore: [{ id: 'GHSA-1', reason: '' }] })).toThrow(DeplyzeError);
  });

  it('defaults are independent objects (no shared mutable state)', () => {
    const a = defaultConfig();
    const b = defaultConfig();
    a.security.failOn.push('low');
    expect(b.security.failOn).toEqual(['critical', 'high']);
  });
});

describe('loadConfig', () => {
  it('discovers .deplyze.yml in the project root', async () => {
    const dir = await tempDir();
    await writeFile(
      path.join(dir, '.deplyze.yml'),
      [
        'version: 1',
        'licenses:',
        '  denied:',
        '    - AGPL-3.0',
        'security:',
        '  failOn:',
        '    - critical',
      ].join('\n'),
    );
    const config = await loadConfig(dir);
    expect(config.licenses.denied).toEqual(['AGPL-3.0']);
    expect(config.configPath).toBe(path.join(dir, '.deplyze.yml'));
  });

  it('returns defaults when no config file exists', async () => {
    const dir = await tempDir();
    const config = await loadConfig(dir);
    expect(config.configPath).toBeUndefined();
    expect(config.security.failOn).toEqual(['critical', 'high']);
  });

  it('honours an explicit --config path', async () => {
    const dir = await tempDir();
    await writeFile(path.join(dir, 'custom.json'), JSON.stringify({ security: { failOn: ['medium'] } }));
    const config = await loadConfig(dir, { explicitPath: 'custom.json' });
    expect(config.security.failOn).toEqual(['medium']);
  });

  it('fails clearly when an explicit config is missing', async () => {
    const dir = await tempDir();
    await expect(loadConfig(dir, { explicitPath: 'missing.yml' })).rejects.toBeInstanceOf(DeplyzeError);
  });

  it('reports malformed YAML as a configuration error', async () => {
    const dir = await tempDir();
    const file = path.join(dir, '.deplyze.yml');
    await writeFile(file, 'version: 1\n  bad: [unclosed');
    await expect(loadConfigFile(file)).rejects.toBeInstanceOf(DeplyzeError);
  });

  it('loads a JS config module', async () => {
    const dir = await tempDir();
    const file = path.join(dir, 'deplyze.config.mjs');
    await writeFile(file, 'export default { security: { failOn: ["high"] } };\n');
    const config = await loadConfigFile(file);
    expect(config.security.failOn).toEqual(['high']);
  });
});
