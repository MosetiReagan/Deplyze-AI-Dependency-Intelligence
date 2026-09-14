import { mkdtemp, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { RegistryClient, encodePackageName, normalizePackument } from '../src/index.js';

const dirs: string[] = [];
async function tempDir(): Promise<string> {
  const dir = await mkdtemp(path.join(os.tmpdir(), 'deplyze-reg-'));
  dirs.push(dir);
  return dir;
}
afterEach(async () => {
  await Promise.all(dirs.splice(0).map((dir) => rm(dir, { recursive: true, force: true })));
});

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });
}

describe('encodePackageName', () => {
  it('encodes scoped names but keeps the @', () => {
    expect(encodePackageName('lodash')).toBe('lodash');
    expect(encodePackageName('@scope/thing')).toBe('@scope%2fthing');
  });
});

describe('normalizePackument', () => {
  it('normalizes versions, licenses, deprecation, scripts and bin', () => {
    const metadata = normalizePackument('example', {
      name: 'example',
      'dist-tags': { latest: '2.0.0' },
      time: { created: '2020-01-01T00:00:00Z', '2.0.0': '2024-01-01T00:00:00Z' },
      maintainers: [{ name: 'someone' }],
      repository: { url: 'https://github.com/example/example' },
      versions: {
        '1.0.0': { version: '1.0.0', license: 'MIT', deprecated: 'use v2' },
        '2.0.0': {
          version: '2.0.0',
          license: { type: 'Apache-2.0' },
          scripts: { postinstall: 'node setup.js' },
          bin: { example: './cli.js' },
          dependencies: { lodash: '^4.0.0' },
        },
      },
    });
    expect(metadata.latest).toBe('2.0.0');
    expect(metadata.versions.map((version) => version.version)).toEqual(['2.0.0', '1.0.0']);
    expect(metadata.versions[1]?.deprecated).toBe('use v2');
    expect(metadata.versions[0]?.license).toBe('Apache-2.0');
    expect(metadata.versions[0]?.scripts?.postinstall).toBe('node setup.js');
    expect(metadata.versions[0]?.bin).toEqual({ example: './cli.js' });
    expect(metadata.repository).toBe('https://github.com/example/example');
    expect(metadata.time?.created).toBe('2020-01-01T00:00:00Z');
  });

  it('handles a string bin and a legacy licenses array', () => {
    const metadata = normalizePackument('@scope/pkg', {
      versions: {
        '1.0.0': { version: '1.0.0', licenses: [{ type: 'MIT' }, { type: 'ISC' }], bin: './bin.js' },
      },
    });
    expect(metadata.versions[0]?.license).toBe('MIT OR ISC');
    expect(metadata.versions[0]?.bin).toEqual({ pkg: './bin.js' });
  });
});

describe('RegistryClient', () => {
  it('fetches and caches metadata, then serves it from cache', async () => {
    const directory = await tempDir();
    let calls = 0;
    const fetchImpl = vi.fn(async () => {
      calls += 1;
      return json({
        name: 'lodash',
        'dist-tags': { latest: '4.17.21' },
        versions: { '4.17.21': { version: '4.17.21', license: 'MIT' } },
      });
    }) as unknown as typeof fetch;
    const client = new RegistryClient({ cacheDirectory: directory, fetchImpl });
    const metadata = await client.getMetadata('lodash');
    expect(metadata?.latest).toBe('4.17.21');
    expect(calls).toBe(1);
    await client.getMetadata('lodash');
    expect(calls).toBe(1);
  });

  it('refuses to query unsafe package names (no SSRF)', async () => {
    const fetchImpl = vi.fn(async () => json({})) as unknown as typeof fetch;
    const client = new RegistryClient({ cacheDirectory: await tempDir(), fetchImpl });
    const metadata = await client.getMetadata('../../etc/passwd');
    expect(metadata).toBeUndefined();
    expect(fetchImpl).not.toHaveBeenCalled();
  });

  it('returns undefined for a 404 without throwing', async () => {
    const directory = await tempDir();
    const client = new RegistryClient({
      cacheDirectory: directory,
      retries: 0,
      fetchImpl: (async () => json({}, 404)) as unknown as typeof fetch,
    });
    expect(await client.getMetadata('does-not-exist')).toBeUndefined();
  });

  it('does not touch the network in offline mode', async () => {
    const directory = await tempDir();
    const fetchImpl = vi.fn(async () => json({})) as unknown as typeof fetch;
    const client = new RegistryClient({ cacheDirectory: directory, offline: true, fetchImpl });
    expect(await client.getMetadata('lodash')).toBeUndefined();
    expect(fetchImpl).not.toHaveBeenCalled();
  });
});
