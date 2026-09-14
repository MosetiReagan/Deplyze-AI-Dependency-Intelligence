import { mkdir, readFile, writeFile, rename, readdir, stat } from 'node:fs/promises';
import path from 'node:path';
import { shortHash } from '@deplyze/core';

export interface CacheEntry<T> {
  fetchedAt: string;
  schema: number;
  value: T;
}

export interface CacheOptions {
  directory: string;
  /** Time-to-live in milliseconds. `0` disables expiry. */
  ttlMs?: number;
  namespace?: string;
  now?: () => number;
}

const CACHE_SCHEMA = 1;

/**
 * Small, dependency-free disk cache.
 *
 * Entries are written atomically (temp file + rename) so a killed process can
 * never leave a half-written entry that later parses as valid. Keys are hashed
 * before touching the filesystem, which means an advisory id containing `/`,
 * `..` or NUL cannot influence path traversal.
 */
export class DiskCache<T> {
  private readonly directory: string;
  private readonly ttlMs: number;
  private readonly namespace: string;
  private readonly now: () => number;
  private readonly memo = new Map<string, CacheEntry<T> | null>();
  private ready: Promise<void> | undefined;

  constructor(options: CacheOptions) {
    this.directory = path.join(options.directory, options.namespace ?? 'default');
    this.ttlMs = options.ttlMs ?? 6 * 60 * 60 * 1000;
    this.namespace = options.namespace ?? 'default';
    this.now = options.now ?? Date.now;
  }

  private fileFor(key: string): string {
    const safe = `${shortHash(key, 40)}.json`;
    return path.join(this.directory, safe);
  }

  private async ensureDirectory(): Promise<void> {
    this.ready ??= mkdir(this.directory, { recursive: true }).then(() => undefined);
    await this.ready;
  }

  private isFresh(entry: CacheEntry<T>): boolean {
    if (this.ttlMs <= 0) return true;
    if (entry.schema !== CACHE_SCHEMA) return false;
    const fetchedAt = Date.parse(entry.fetchedAt);
    if (Number.isNaN(fetchedAt)) return false;
    return this.now() - fetchedAt < this.ttlMs;
  }

  async get(key: string, options: { allowStale?: boolean } = {}): Promise<CacheEntry<T> | undefined> {
    if (this.memo.has(key)) {
      const memoized = this.memo.get(key);
      if (!memoized) return undefined;
      if (options.allowStale || this.isFresh(memoized)) return memoized;
      return undefined;
    }
    try {
      const raw = await readFile(this.fileFor(key), 'utf8');
      const parsed = JSON.parse(raw) as CacheEntry<T>;
      if (!parsed || typeof parsed !== 'object' || parsed.schema !== CACHE_SCHEMA) {
        this.memo.set(key, null);
        return undefined;
      }
      this.memo.set(key, parsed);
      if (options.allowStale || this.isFresh(parsed)) return parsed;
      return undefined;
    } catch {
      this.memo.set(key, null);
      return undefined;
    }
  }

  async set(key: string, value: T): Promise<void> {
    const entry: CacheEntry<T> = {
      fetchedAt: new Date(this.now()).toISOString(),
      schema: CACHE_SCHEMA,
      value,
    };
    this.memo.set(key, entry);
    await this.ensureDirectory();
    const target = this.fileFor(key);
    const temp = `${target}.${process.pid}.${Math.random().toString(36).slice(2, 8)}.tmp`;
    await writeFile(temp, JSON.stringify(entry), 'utf8');
    await rename(temp, target);
  }

  /** Read every cached value. Used by offline scans to match cached advisories. */
  async allEntries(): Promise<T[]> {
    const values: T[] = [];
    try {
      for (const name of await readdir(this.directory)) {
        if (!name.endsWith('.json')) continue;
        try {
          const parsed = JSON.parse(await readFile(path.join(this.directory, name), 'utf8')) as CacheEntry<T>;
          if (parsed && parsed.schema === CACHE_SCHEMA) values.push(parsed.value);
        } catch {
          /* skip corrupt entries */
        }
      }
    } catch {
      /* directory does not exist */
    }
    return values;
  }

  async stats(): Promise<{ entries: number; bytes: number; directory: string; namespace: string }> {
    let entries = 0;
    let bytes = 0;
    try {
      for (const name of await readdir(this.directory)) {
        if (!name.endsWith('.json')) continue;
        entries += 1;
        try {
          bytes += (await stat(path.join(this.directory, name))).size;
        } catch {
          /* ignore */
        }
      }
    } catch {
      /* directory does not exist yet */
    }
    return { entries, bytes, directory: this.directory, namespace: this.namespace };
  }

  async clear(): Promise<void> {
    this.memo.clear();
    try {
      const names = await readdir(this.directory);
      await Promise.all(
        names
          .filter((name) => name.endsWith('.json'))
          .map(async (name) => {
            await (await import('node:fs/promises')).rm(path.join(this.directory, name), { force: true });
          }),
      );
    } catch {
      /* nothing to clear */
    }
  }
}
