import { DeplyzeError, ErrorCode, Logger, assertSafePackageName, compareVersions } from '@deplyze/core';
import { DiskCache } from '@deplyze/advisories';

export interface RegistryVersionInfo {
  version: string;
  license?: string;
  deprecated?: string;
  scripts?: Record<string, string>;
  engines?: Record<string, string>;
  dependencies?: Record<string, string>;
  unpackedSize?: number;
  publishedAt?: string;
  bin?: Record<string, string>;
}

export interface RegistryMetadata {
  name: string;
  latest?: string;
  distTags?: Record<string, string>;
  versions: RegistryVersionInfo[];
  maintainers?: Array<{ name?: string; email?: string }>;
  repository?: string;
  homepage?: string;
  /** Timestamps for `created`/`modified` and each published version. */
  time?: Record<string, string>;
  fromCache: boolean;
  fetchedAt: string;
}

export interface RegistryClientOptions {
  baseUrl?: string;
  timeoutMs?: number;
  retries?: number;
  concurrency?: number;
  cacheDirectory?: string;
  cacheTtlMs?: number;
  offline?: boolean;
  enabled?: boolean;
  logger?: Logger;
  maxResponseBytes?: number;
  fetchImpl?: typeof fetch;
}

const PACKUMENT_ACCEPT = 'application/json';

interface RawPackument {
  name?: string;
  'dist-tags'?: Record<string, string>;
  versions?: Record<string, RawVersion>;
  time?: Record<string, string>;
  maintainers?: Array<{ name?: string; email?: string }>;
  repository?: { url?: string } | string;
  homepage?: string;
}

interface RawVersion {
  version?: string;
  license?: string | { type?: string };
  licenses?: Array<{ type?: string }>;
  deprecated?: string;
  scripts?: Record<string, string>;
  engines?: Record<string, string>;
  dependencies?: Record<string, string>;
  dist?: { unpackedSize?: number };
  bin?: Record<string, string> | string;
}

/**
 * npm-compatible registry client.
 *
 * Only three request shapes are ever issued: a packument for a specific,
 * validated package name, a dist-tag lookup, and a download-count lookup. The
 * package name is validated before it reaches the URL, which prevents a
 * malicious lockfile entry from turning the scanner into an SSRF proxy.
 */
export class RegistryClient {
  private readonly cache: DiskCache<RegistryMetadata>;
  private readonly options: Required<
    Pick<
      RegistryClientOptions,
      'baseUrl' | 'timeoutMs' | 'retries' | 'concurrency' | 'offline' | 'enabled' | 'maxResponseBytes'
    >
  > &
    RegistryClientOptions;
  private readonly log: Logger;
  private readonly fetchImpl: typeof fetch;
  private readonly inflight = new Map<string, Promise<RegistryMetadata | undefined>>();
  private readonly memo = new Map<string, RegistryMetadata | undefined>();
  private readonly negative = new Set<string>();

  constructor(options: RegistryClientOptions = {}) {
    this.options = {
      baseUrl: options.baseUrl ?? 'https://registry.npmjs.org',
      timeoutMs: options.timeoutMs ?? 15_000,
      retries: options.retries ?? 1,
      concurrency: options.concurrency ?? 8,
      offline: options.offline ?? false,
      enabled: options.enabled ?? true,
      maxResponseBytes: options.maxResponseBytes ?? 24 * 1024 * 1024,
      ...options,
    };
    this.cache = new DiskCache<RegistryMetadata>({
      directory: options.cacheDirectory ?? '.deplyze-cache/registry',
      ttlMs: options.cacheTtlMs ?? 6 * 60 * 60 * 1000,
      namespace: 'npm',
    });
    this.log = options.logger ?? new Logger({ level: 'silent' });
    this.fetchImpl = options.fetchImpl ?? fetch;
  }

  get offline(): boolean {
    return this.options.offline === true;
  }

  get enabled(): boolean {
    return this.options.enabled === true && !this.offline;
  }

  async cacheStats(): Promise<{ entries: number; bytes: number; directory: string }> {
    return this.cache.stats();
  }

  /** Fetch metadata for many packages with bounded concurrency. */
  async metadataFor(
    names: string[],
    options: { limit?: number } = {},
  ): Promise<Map<string, RegistryMetadata>> {
    const unique = [...new Set(names)];
    const limit = options.limit ?? this.options.concurrency;
    const results = new Map<string, RegistryMetadata>();
    let cursor = 0;
    const workers = Array.from({ length: Math.max(1, Math.min(limit, unique.length)) }, async () => {
      while (true) {
        const index = cursor;
        cursor += 1;
        if (index >= unique.length) return;
        const name = unique[index] as string;
        const metadata = await this.getMetadata(name);
        if (metadata) results.set(name, metadata);
      }
    });
    await Promise.all(workers);
    return results;
  }

  async getMetadata(name: string): Promise<RegistryMetadata | undefined> {
    if (this.memo.has(name)) return this.memo.get(name);
    if (this.negative.has(name)) return undefined;
    const existing = this.inflight.get(name);
    if (existing) return existing;

    const promise = this.loadMetadata(name).finally(() => this.inflight.delete(name));
    this.inflight.set(name, promise);
    return promise;
  }

  private async loadMetadata(name: string): Promise<RegistryMetadata | undefined> {
    const cached = await this.cache.get(name, { allowStale: this.offline });
    if (cached) {
      const value = { ...cached.value, fromCache: true };
      this.memo.set(name, value);
      return value;
    }
    if (!this.enabled) {
      this.negative.add(name);
      return undefined;
    }
    try {
      assertSafePackageName(name);
    } catch {
      this.log.warn('Refused to query the registry for an unsafe package name', { name });
      this.negative.add(name);
      return undefined;
    }

    const url = `${this.options.baseUrl.replace(/\/$/, '')}/${encodePackageName(name)}`;
    try {
      const body = await this.requestJson(url, { accept: PACKUMENT_ACCEPT });
      const metadata = normalizePackument(name, body);
      await this.cache.set(name, { ...metadata, fromCache: false });
      this.memo.set(name, { ...metadata, fromCache: false });
      return { ...metadata, fromCache: false };
    } catch (error) {
      if (error instanceof DeplyzeError && error.code === ErrorCode.DEPLYZE_E_REGISTRY) {
        this.log.debug('Registry returned no usable metadata', { name, error: error.message });
        const notFound = await this.cache.get(name, { allowStale: true });
        if (notFound) {
          this.memo.set(name, { ...notFound.value, fromCache: true });
          return { ...notFound.value, fromCache: true };
        }
        this.negative.add(name);
        return undefined;
      }
      this.log.warn('Registry request failed', { name, error: String(error) });
      return undefined;
    }
  }

  /** Weekly download count from the npm downloads API. */
  async weeklyDownloads(name: string): Promise<number | undefined> {
    if (!this.enabled) return undefined;
    try {
      assertSafePackageName(name);
    } catch {
      return undefined;
    }
    try {
      const body = (await this.requestJson(
        `https://api.npmjs.org/downloads/point/last-week/${encodePackageName(name)}`,
        { accept: 'application/json' },
      )) as { downloads?: number };
      return typeof body?.downloads === 'number' ? body.downloads : undefined;
    } catch {
      return undefined;
    }
  }

  private async requestJson(url: string, headers: Record<string, string>): Promise<unknown> {
    let lastError: unknown;
    for (let attempt = 0; attempt <= (this.options.retries ?? 0); attempt += 1) {
      try {
        const response = await this.fetchImpl(url, {
          method: 'GET',
          headers: { ...headers, 'user-agent': 'deplyze' },
          signal: AbortSignal.timeout(this.options.timeoutMs ?? 15_000),
        });
        if (response.status === 404) {
          throw new DeplyzeError(ErrorCode.DEPLYZE_E_REGISTRY, 'Package not found in the registry.', {
            details: { url },
          });
        }
        if (response.status === 429 || response.status >= 500) {
          lastError = new Error(`HTTP ${response.status}`);
          await delay(400 * 2 ** attempt);
          continue;
        }
        if (!response.ok) {
          throw new DeplyzeError(
            ErrorCode.DEPLYZE_E_REGISTRY,
            `Registry request failed with HTTP ${response.status}.`,
          );
        }
        const declared = Number(response.headers.get('content-length') ?? '0');
        if (declared > (this.options.maxResponseBytes ?? 0)) {
          throw new DeplyzeError(
            ErrorCode.DEPLYZE_E_OVERSIZED_FILE,
            'Registry response exceeded the size limit.',
          );
        }
        const text = await response.text();
        if (text.length > (this.options.maxResponseBytes ?? Number.POSITIVE_INFINITY)) {
          throw new DeplyzeError(
            ErrorCode.DEPLYZE_E_OVERSIZED_FILE,
            'Registry response exceeded the size limit.',
          );
        }
        return JSON.parse(text);
      } catch (error) {
        if (error instanceof DeplyzeError && error.code !== ErrorCode.DEPLYZE_E_REGISTRY) throw error;
        lastError = error;
        if (attempt < (this.options.retries ?? 0)) await delay(400 * 2 ** attempt);
      }
    }
    if (lastError instanceof DeplyzeError) throw lastError;
    throw new DeplyzeError(ErrorCode.DEPLYZE_E_NETWORK, 'Could not reach the npm registry.', {
      cause: lastError,
    });
  }
}

export function encodePackageName(name: string): string {
  // Scoped names keep `@` and encode the separating slash.
  return name.startsWith('@') ? name.replace('/', '%2f') : encodeURIComponent(name);
}

function licenseOf(version: RawVersion): string | undefined {
  if (typeof version.license === 'string') return version.license;
  if (version.license && typeof version.license === 'object' && version.license.type)
    return version.license.type;
  if (Array.isArray(version.licenses)) {
    const types = version.licenses.map((entry) => entry.type).filter((t): t is string => !!t);
    if (types.length > 0) return types.join(' OR ');
  }
  return undefined;
}

export function normalizePackument(name: string, raw: unknown): RegistryMetadata {
  const data = (raw ?? {}) as RawPackument;
  const time = data.time ?? {};
  const versions: RegistryVersionInfo[] = [];
  for (const [version, entry] of Object.entries(data.versions ?? {})) {
    if (!entry || typeof entry !== 'object') continue;
    const info: RegistryVersionInfo = { version: entry.version ?? version };
    const license = licenseOf(entry);
    if (license) info.license = license;
    if (entry.deprecated) info.deprecated = entry.deprecated;
    if (entry.scripts) info.scripts = entry.scripts;
    if (entry.engines) info.engines = entry.engines;
    if (entry.dependencies) info.dependencies = entry.dependencies;
    if (typeof entry.dist?.unpackedSize === 'number') info.unpackedSize = entry.dist.unpackedSize;
    if (entry.bin && typeof entry.bin === 'object') info.bin = entry.bin;
    else if (typeof entry.bin === 'string') info.bin = { [name.replace(/^@[^/]+\//, '')]: entry.bin };
    const publishedAt = time[version];
    if (publishedAt) info.publishedAt = publishedAt;
    versions.push(info);
  }
  versions.sort((a, b) => compareVersions(b.version, a.version));

  const repository =
    typeof data.repository === 'string' ? data.repository : (data.repository?.url ?? undefined);

  const metadata: RegistryMetadata = {
    name: data.name ?? name,
    versions,
    fromCache: false,
    fetchedAt: new Date().toISOString(),
  };
  const latest = data['dist-tags']?.latest;
  if (latest) metadata.latest = latest;
  if (data['dist-tags']) metadata.distTags = data['dist-tags'];
  if (data.maintainers) metadata.maintainers = data.maintainers;
  if (repository) metadata.repository = repository;
  if (data.homepage) metadata.homepage = data.homepage;
  if (data.time) metadata.time = data.time;
  return metadata;
}

function delay(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
