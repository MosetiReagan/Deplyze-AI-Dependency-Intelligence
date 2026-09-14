import { DeplyzeError, ErrorCode, Logger } from '@deplyze/core';
import { z } from 'zod';
import { DiskCache } from './cache.js';
import { normalizeOsv, osvVulnerabilitySchema, type OsvVulnerability } from './normalize.js';
import type { Advisory, Ecosystem } from '@deplyze/core';

export const OSV_API_BASE = 'https://api.osv.dev/v1';

const queryBatchResponseSchema = z.object({
  results: z.array(
    z.object({ vulns: z.array(z.object({ id: z.string(), modified: z.string().optional() })).optional() }),
  ),
});

const queryResponseSchema = z.object({ vulns: z.array(z.unknown()).optional() });

export interface OsvQuery {
  name: string;
  version: string;
  ecosystem: Ecosystem;
}

/** OSV ecosystem identifiers differ from Deplyze's internal names. */
const OSV_ECOSYSTEM: Partial<Record<Ecosystem, string>> = {
  npm: 'npm',
  pypi: 'PyPI',
  cargo: 'crates.io',
  go: 'Go',
  maven: 'Maven',
  nuget: 'NuGet',
  composer: 'Packagist',
  gem: 'RubyGems',
};

export interface OsvClientOptions {
  baseUrl?: string;
  /** Milliseconds before an HTTP request is aborted. */
  timeoutMs?: number;
  /** Max retry attempts for transient failures (5xx, network errors). */
  retries?: number;
  /** Max ids fetched concurrently when hydrating advisory details. */
  concurrency?: number;
  cacheDirectory?: string;
  cacheTtlMs?: number;
  offline?: boolean;
  logger?: Logger;
  maxResponseBytes?: number;
  /** Injectable fetch implementation, used by tests. */
  fetchImpl?: typeof fetch;
}

export interface AdvisoryQueryResult {
  advisories: Advisory[];
  /** Advisory ids that could not be hydrated (offline, network, oversized). */
  unresolved: string[];
  /** True when at least one network request was made. */
  usedNetwork: boolean;
  /** True when results came (partly) from cache. */
  usedCache: boolean;
}

export class OsvClient {
  private readonly options: Required<
    Pick<
      OsvClientOptions,
      'baseUrl' | 'timeoutMs' | 'retries' | 'concurrency' | 'offline' | 'maxResponseBytes'
    >
  > &
    OsvClientOptions;
  private readonly cache: DiskCache<OsvVulnerability>;
  private readonly log: Logger;
  private readonly fetchImpl: typeof fetch;

  constructor(options: OsvClientOptions = {}) {
    this.options = {
      baseUrl: options.baseUrl ?? OSV_API_BASE,
      timeoutMs: options.timeoutMs ?? 20_000,
      retries: options.retries ?? 2,
      concurrency: options.concurrency ?? 8,
      offline: options.offline ?? false,
      maxResponseBytes: options.maxResponseBytes ?? 8 * 1024 * 1024,
      ...options,
    };
    this.cache = new DiskCache<OsvVulnerability>({
      directory: options.cacheDirectory ?? '.deplyze-cache/advisories',
      ttlMs: options.cacheTtlMs ?? 6 * 60 * 60 * 1000,
      namespace: 'osv',
    });
    this.log = options.logger ?? new Logger({ level: 'silent' });
    this.fetchImpl = options.fetchImpl ?? fetch;
  }

  get offline(): boolean {
    return this.options.offline === true;
  }

  async cacheStats(): Promise<{ entries: number; bytes: number; directory: string }> {
    return this.cache.stats();
  }

  /**
   * Query advisories for a batch of resolved packages.
   *
   * Uses OSV's batch endpoint to keep request counts low, then hydrates only
   * the advisory ids that are not already in the local cache.
   */
  async queryBatch(queries: OsvQuery[]): Promise<AdvisoryQueryResult> {
    const result: AdvisoryQueryResult = {
      advisories: [],
      unresolved: [],
      usedNetwork: false,
      usedCache: false,
    };
    if (queries.length === 0) return result;

    const deduped = new Map<string, OsvQuery>();
    for (const query of queries) {
      deduped.set(`${query.ecosystem}:${query.name}@${query.version}`, query);
    }
    const uniqueQueries = [...deduped.values()];

    const idSet = new Set<string>();
    if (!this.offline) {
      const ids = await this.queryIds(uniqueQueries);
      // The batch lookup is a real network round-trip even when every advisory
      // detail is later served from cache.
      result.usedNetwork = true;
      for (const id of ids) idSet.add(id);
    } else {
      // Offline mode cannot discover new ids; instead we look for cached
      // advisories that match the queried packages.
      result.usedCache = true;
      const cached = await this.findCachedAdvisories(uniqueQueries);
      for (const advisory of cached) result.advisories.push(advisory);
      return result;
    }

    const toFetch: string[] = [];
    const cachedVulns = new Map<string, OsvVulnerability>();
    for (const id of idSet) {
      const cached = await this.cache.get(id, { allowStale: this.offline });
      if (cached) {
        cachedVulns.set(id, cached.value);
        result.usedCache = true;
      } else {
        toFetch.push(id);
      }
    }

    const fetched = await this.mapConcurrent(toFetch, this.options.concurrency, async (id) => {
      try {
        const vuln = await this.fetchVulnerability(id);
        await this.cache.set(id, vuln);
        return vuln;
      } catch (error) {
        this.log.warn(`Could not hydrate advisory ${id}`, { error: String(error) });
        result.unresolved.push(id);
        return undefined;
      }
    });

    for (const vuln of [...cachedVulns.values(), ...fetched.filter(Boolean)]) {
      if (!vuln) continue;
      const advisories = normalizeOsv(vuln, { source: 'osv' });
      for (const advisory of advisories) result.advisories.push(advisory);
    }

    const relevant = this.filterToQueried(result.advisories, uniqueQueries);
    return { ...result, advisories: relevant };
  }

  private filterToQueried(advisories: Advisory[], queries: OsvQuery[]): Advisory[] {
    const key = (ecosystem: string, name: string) => `${ecosystem}:${name}`;
    const wanted = new Set(queries.map((query) => key(query.ecosystem, query.name)));
    return advisories.filter((advisory) => wanted.has(key(advisory.ecosystem, advisory.package)));
  }

  private async findCachedAdvisories(queries: OsvQuery[]): Promise<Advisory[]> {
    const wanted = new Set(queries.map((query) => `${query.ecosystem}:${query.name}`));
    const found: Advisory[] = [];
    const stats = await this.cache.stats();
    if (stats.entries > 0) {
      const entries = await this.cache.allEntries();
      for (const entry of entries) {
        const advisories = normalizeOsv(entry, { source: 'osv-cache', fromCache: true });
        for (const advisory of advisories) {
          if (wanted.has(`${advisory.ecosystem}:${advisory.package}`)) found.push(advisory);
        }
      }
    }
    return found;
  }

  private async queryIds(queries: OsvQuery[]): Promise<string[]> {
    const payload = {
      queries: queries.map((query) => ({
        package: { name: query.name, ecosystem: OSV_ECOSYSTEM[query.ecosystem] ?? query.ecosystem },
        version: query.version,
      })),
    };
    const body = await this.postJson(`${this.options.baseUrl}/querybatch`, payload);
    const parsed = queryBatchResponseSchema.safeParse(body);
    if (!parsed.success) {
      throw new DeplyzeError(ErrorCode.DEPLYZE_E_ADVISORY, 'OSV returned an unexpected response shape.', {
        hint: 'This usually indicates an API change. Try again later or run with --offline.',
      });
    }
    const ids = new Set<string>();
    for (const entry of parsed.data.results) {
      for (const vuln of entry.vulns ?? []) ids.add(vuln.id);
    }
    return [...ids];
  }

  async fetchVulnerability(id: string): Promise<OsvVulnerability> {
    const body = await this.fetchJson(`${this.options.baseUrl}/vulns/${encodeURIComponent(id)}`);
    const parsed = osvVulnerabilitySchema.safeParse(body);
    if (!parsed.success) {
      throw new DeplyzeError(ErrorCode.DEPLYZE_E_ADVISORY, `Advisory ${id} could not be parsed.`);
    }
    return parsed.data;
  }

  async queryPackageVersion(query: OsvQuery): Promise<Advisory[]> {
    const body = await this.postJson(`${this.options.baseUrl}/query`, {
      package: { name: query.name, ecosystem: OSV_ECOSYSTEM[query.ecosystem] ?? query.ecosystem },
      version: query.version,
    });
    const parsed = queryResponseSchema.safeParse(body);
    if (!parsed.success) return [];
    const advisories: Advisory[] = [];
    for (const raw of parsed.data.vulns ?? []) {
      const vuln = osvVulnerabilitySchema.safeParse(raw);
      if (vuln.success) advisories.push(...normalizeOsv(vuln.data, { source: 'osv' }));
    }
    return advisories;
  }

  private async postJson(url: string, payload: unknown): Promise<unknown> {
    return this.request(url, { method: 'POST', body: JSON.stringify(payload) });
  }

  private async fetchJson(url: string): Promise<unknown> {
    return this.request(url, { method: 'GET' });
  }

  private async request(url: string, init: RequestInit): Promise<unknown> {
    if (this.options.offline) {
      throw new DeplyzeError(
        ErrorCode.DEPLYZE_E_OFFLINE_NO_CACHE,
        'Offline mode is enabled but the requested data is not cached.',
        {
          hint: 'Run once without --offline to populate the cache.',
        },
      );
    }
    let lastError: unknown;
    for (let attempt = 0; attempt <= (this.options.retries ?? 0); attempt += 1) {
      try {
        const response = await this.fetchImpl(url, {
          ...init,
          headers: {
            'content-type': 'application/json',
            accept: 'application/json',
            'user-agent': 'deplyze',
          },
          signal: AbortSignal.timeout(this.options.timeoutMs ?? 20_000),
        });
        if (response.status >= 500 || response.status === 429) {
          lastError = new Error(`OSV responded with HTTP ${response.status}`);
          await this.sleep(backoffMs(attempt, response.headers.get('retry-after')));
          continue;
        }
        if (!response.ok) {
          throw new DeplyzeError(
            ErrorCode.DEPLYZE_E_ADVISORY,
            `OSV request failed with HTTP ${response.status}.`,
            {
              hint: 'Check network access to api.osv.dev, or run with --offline to use cached data.',
            },
          );
        }
        return await readLimitedJson(response, this.options.maxResponseBytes ?? 8 * 1024 * 1024);
      } catch (error) {
        if (error instanceof DeplyzeError) throw error;
        lastError = error;
        this.log.debug('OSV request error', { attempt, error: String(error) });
        if (attempt < (this.options.retries ?? 0)) await this.sleep(backoffMs(attempt, null));
      }
    }
    throw new DeplyzeError(
      ErrorCode.DEPLYZE_E_NETWORK,
      `Could not reach the advisory service at ${new URL(url).host}.`,
      {
        hint: 'Check connectivity, or run with --offline to use cached advisory data.',
        cause: lastError,
      },
    );
  }

  private sleep(ms: number): Promise<void> {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }

  private async mapConcurrent<I, O>(
    items: I[],
    limit: number,
    worker: (item: I) => Promise<O>,
  ): Promise<O[]> {
    const results: O[] = new Array(items.length) as O[];
    let cursor = 0;
    const width = Math.max(1, Math.min(limit, items.length));
    const runners = Array.from({ length: width }, async () => {
      while (true) {
        const index = cursor;
        cursor += 1;
        if (index >= items.length) return;
        results[index] = await worker(items[index] as I);
      }
    });
    await Promise.all(runners);
    return results;
  }
}

function backoffMs(attempt: number, retryAfter: string | null): number {
  if (retryAfter) {
    const seconds = Number(retryAfter);
    if (Number.isFinite(seconds) && seconds >= 0) return Math.min(seconds * 1000, 30_000);
  }
  const base = Math.min(500 * 2 ** attempt, 8_000);
  return base + Math.floor(Math.random() * 250);
}

async function readLimitedJson(response: Response, maxBytes: number): Promise<unknown> {
  const contentLength = response.headers.get('content-length');
  if (contentLength && Number(contentLength) > maxBytes) {
    throw new DeplyzeError(ErrorCode.DEPLYZE_E_OVERSIZED_FILE, 'Advisory response exceeded the size limit.');
  }
  const text = await response.text();
  if (text.length > maxBytes) {
    throw new DeplyzeError(ErrorCode.DEPLYZE_E_OVERSIZED_FILE, 'Advisory response exceeded the size limit.');
  }
  try {
    return JSON.parse(text);
  } catch (error) {
    throw new DeplyzeError(ErrorCode.DEPLYZE_E_ADVISORY, 'Advisory response was not valid JSON.', {
      cause: error,
    });
  }
}
