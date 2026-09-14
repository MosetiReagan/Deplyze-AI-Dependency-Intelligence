import { mkdtemp, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { OsvClient } from '../src/index.js';

const VULN = {
  id: 'GHSA-test-0001-0001',
  summary: 'Test advisory for lodash',
  severity: [{ type: 'CVSS_V3', score: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' }],
  affected: [
    {
      package: { ecosystem: 'npm', name: 'lodash' },
      ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '4.17.21' }] }],
    },
  ],
};

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' },
  });
}

let directory: string | undefined;

afterEach(async () => {
  if (directory) await rm(directory, { recursive: true, force: true });
  directory = undefined;
});

describe('OsvClient', () => {
  it('queries ids then hydrates advisories', async () => {
    directory = await mkdtemp(path.join(os.tmpdir(), 'deplyze-osv-'));
    const fetchImpl = vi.fn(async (input: string | URL | Request) => {
      const url = String(input);
      if (url.endsWith('/querybatch')) {
        return json({
          results: [{ vulns: [{ id: 'GHSA-test-0001-0001', modified: '2024-01-01T00:00:00Z' }] }],
        });
      }
      if (url.includes('/vulns/')) return json(VULN);
      throw new Error(`Unexpected URL ${url}`);
    }) as unknown as typeof fetch;

    const client = new OsvClient({ cacheDirectory: directory, fetchImpl });
    const result = await client.queryBatch([{ name: 'lodash', version: '4.17.20', ecosystem: 'npm' }]);

    expect(result.usedNetwork).toBe(true);
    expect(result.advisories).toHaveLength(1);
    expect(result.advisories[0]?.package).toBe('lodash');
    expect(result.advisories[0]?.fixedVersions).toEqual(['4.17.21']);
    expect(result.unresolved).toEqual([]);
  });

  it('reuses cached advisory details on the next run', async () => {
    directory = await mkdtemp(path.join(os.tmpdir(), 'deplyze-osv-'));
    const hydrateUrls: string[] = [];
    const makeFetch = () =>
      vi.fn(async (input: string | URL | Request) => {
        const url = String(input);
        if (url.endsWith('/querybatch')) return json({ results: [{ vulns: [{ id: VULN.id }] }] });
        hydrateUrls.push(url);
        return json(VULN);
      }) as unknown as typeof fetch;

    await new OsvClient({ cacheDirectory: directory, fetchImpl: makeFetch() }).queryBatch([
      { name: 'lodash', version: '4.17.20', ecosystem: 'npm' },
    ]);
    expect(hydrateUrls).toHaveLength(1);

    const second = await new OsvClient({ cacheDirectory: directory, fetchImpl: makeFetch() }).queryBatch([
      { name: 'lodash', version: '4.17.20', ecosystem: 'npm' },
    ]);
    expect(hydrateUrls).toHaveLength(1);
    expect(second.usedCache).toBe(true);
    expect(second.advisories).toHaveLength(1);
  });

  it('serves matching advisories from cache when offline', async () => {
    directory = await mkdtemp(path.join(os.tmpdir(), 'deplyze-osv-'));
    const fetchImpl = vi.fn(async (input: string | URL | Request) => {
      const url = String(input);
      if (url.endsWith('/querybatch')) return json({ results: [{ vulns: [{ id: VULN.id }] }] });
      return json(VULN);
    }) as unknown as typeof fetch;

    await new OsvClient({ cacheDirectory: directory, fetchImpl }).queryBatch([
      { name: 'lodash', version: '4.17.20', ecosystem: 'npm' },
    ]);

    const offlineFetch = vi.fn(async () => {
      throw new Error('offline client must not use the network');
    }) as unknown as typeof fetch;
    const offline = new OsvClient({ cacheDirectory: directory, fetchImpl: offlineFetch, offline: true });
    const result = await offline.queryBatch([{ name: 'lodash', version: '4.17.20', ecosystem: 'npm' }]);
    expect(result.usedCache).toBe(true);
    expect(result.usedNetwork).toBe(false);
    expect(result.advisories[0]?.fromCache).toBe(true);
    expect(offlineFetch).not.toHaveBeenCalled();
  });

  it('deduplicates identical package queries', async () => {
    directory = await mkdtemp(path.join(os.tmpdir(), 'deplyze-osv-'));
    let batchCalls = 0;
    const fetchImpl = vi.fn(async (input: string | URL | Request) => {
      const url = String(input);
      if (url.endsWith('/querybatch')) {
        batchCalls += 1;
        return json({ results: [{}, {}] });
      }
      return json(VULN);
    }) as unknown as typeof fetch;
    await new OsvClient({ cacheDirectory: directory, fetchImpl }).queryBatch([
      { name: 'lodash', version: '4.17.20', ecosystem: 'npm' },
      { name: 'lodash', version: '4.17.20', ecosystem: 'npm' },
    ]);
    expect(batchCalls).toBe(1);
  });

  it('records advisory ids it could not retrieve instead of inventing data', async () => {
    directory = await mkdtemp(path.join(os.tmpdir(), 'deplyze-osv-'));
    const fetchImpl = vi.fn(async (input: string | URL | Request) => {
      const url = String(input);
      if (url.endsWith('/querybatch')) return json({ results: [{ vulns: [{ id: 'GHSA-broken' }] }] });
      return json({ error: 'boom' }, 400);
    }) as unknown as typeof fetch;
    const client = new OsvClient({ cacheDirectory: directory, fetchImpl, retries: 0 });
    const result = await client.queryBatch([{ name: 'lodash', version: '4.17.20', ecosystem: 'npm' }]);
    expect(result.advisories).toEqual([]);
    expect(result.unresolved).toEqual(['GHSA-broken']);
  });
});
