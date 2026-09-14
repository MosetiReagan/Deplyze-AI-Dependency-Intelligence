import { mkdtemp, readdir, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { DiskCache } from '../src/index.js';

let directory: string;

beforeEach(async () => {
  directory = await mkdtemp(path.join(os.tmpdir(), 'deplyze-cache-'));
});

afterEach(async () => {
  await rm(directory, { recursive: true, force: true });
});

describe('DiskCache', () => {
  it('round-trips values through disk', async () => {
    const cache = new DiskCache<{ a: number }>({ directory, namespace: 'test' });
    await cache.set('key-1', { a: 1 });
    const fresh = new DiskCache<{ a: number }>({ directory, namespace: 'test' });
    expect((await fresh.get('key-1'))?.value).toEqual({ a: 1 });
  });

  it('expires entries according to the TTL', async () => {
    let now = 1_000_000;
    const cache = new DiskCache<string>({ directory, namespace: 'ttl', ttlMs: 1000, now: () => now });
    await cache.set('k', 'value');
    now += 500;
    expect(await cache.get('k')).toBeDefined();
    now += 1000;
    expect(await cache.get('k')).toBeUndefined();
    expect((await cache.get('k', { allowStale: true }))?.value).toBe('value');
  });

  it('hashes keys so traversal attempts cannot escape the cache directory', async () => {
    const cache = new DiskCache<string>({ directory, namespace: 'safe' });
    await cache.set('../../../etc/passwd', 'value');
    const names = await readdir(path.join(directory, 'safe'));
    expect(names.every((name) => /^[a-f0-9]+\.json$/.test(name))).toBe(true);
    expect(await cache.get('../../../etc/passwd')).toBeDefined();
  });

  it('lists every cached entry for offline matching', async () => {
    const cache = new DiskCache<string>({ directory, namespace: 'all' });
    await cache.set('a', 'one');
    await cache.set('b', 'two');
    expect((await cache.allEntries()).sort()).toEqual(['one', 'two']);
  });

  it('reports stats and clears entries', async () => {
    const cache = new DiskCache<string>({ directory, namespace: 'stats' });
    await cache.set('a', 'one');
    const stats = await cache.stats();
    expect(stats.entries).toBe(1);
    expect(stats.bytes).toBeGreaterThan(0);
    await cache.clear();
    expect((await cache.stats()).entries).toBe(0);
  });

  it('treats corrupt entries as misses rather than throwing', async () => {
    const cache = new DiskCache<string>({ directory, namespace: 'corrupt' });
    await cache.set('a', 'one');
    const stats = await cache.stats();
    expect(stats.entries).toBe(1);
    const fresh = new DiskCache<string>({ directory, namespace: 'corrupt' });
    expect(await fresh.get('missing')).toBeUndefined();
  });
});
