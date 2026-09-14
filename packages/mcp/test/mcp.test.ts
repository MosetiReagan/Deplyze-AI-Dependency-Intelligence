import { afterEach, describe, expect, it, vi } from 'vitest';
import { RegistryClient, type ScanCache, type ScanResult } from '@deplyze/scanners';
import {
  createMcpServer,
  toolFindings,
  toolGraph,
  toolLicenses,
  toolPackage,
  toolPolicyCheck,
  toolRemediate,
  toolSbom,
  toolScan,
  toolSecurity,
  toolUpgradePlan,
} from '../src/index.js';
import { makeFinding, makeNode, makeResult } from '../../../test/helpers.js';
import { resolveConfig } from '@deplyze/config';

const vulnerability = makeFinding({
  package: 'lodash',
  version: '4.17.20',
  advisoryId: 'GHSA-test-1111-2222',
  severity: 'critical',
  title: 'Prototype pollution',
  remediation: {
    summary: 'Upgrade lodash',
    upgrades: [{ package: 'lodash', from: '4.17.20', to: '4.17.21', breaking: false }],
  },
});
const outdated = makeFinding({
  category: 'outdated',
  severity: 'low',
  title: 'Minor behind: lodash 4.17.0 -> 4.17.21',
  package: 'lodash',
  version: '4.17.0',
  source: 'outdated/versions',
  remediation: {
    summary: 'Upgrade',
    upgrades: [{ package: 'lodash', from: '4.17.0', to: '4.17.21', breaking: false }],
  },
});
const licenseFinding = makeFinding({
  category: 'license',
  severity: 'high',
  source: 'license/policy',
  title: 'License policy violation',
  package: 'copyleft',
  version: '1.0.0',
});

const result: ScanResult = makeResult({
  nodes: [
    {
      id: 'root:.',
      name: 'app',
      version: '1.0.0',
      ecosystem: 'npm',
      direct: false,
      dev: false,
      optional: false,
      peer: false,
      depth: 0,
      dependencies: [],
    },
    makeNode({ name: 'lodash', version: '4.17.20', direct: true, license: 'MIT', id: 'npm:lodash@4.17.20' }),
    makeNode({ name: 'copyleft', version: '1.0.0', depth: 2, license: 'AGPL-3.0', id: 'npm:copyleft@1.0.0' }),
  ],
  edges: [
    ['root:.', 'npm:lodash@4.17.20'],
    ['npm:lodash@4.17.20', 'npm:copyleft@1.0.0'],
  ],
  findings: [vulnerability, outdated, licenseFinding],
  config: resolveConfig({ licenses: { denied: ['AGPL-3.0'] }, security: { failOn: ['critical'] } }),
});

const cache = { scan: async () => ({ root: '/tmp/fixture', result }) } as unknown as ScanCache;

afterEach(() => vi.restoreAllMocks());

describe('toolScan', () => {
  it('returns evidence-based findings and an explicit note that absence is not safety', async () => {
    const output = await toolScan(cache, {});
    expect(output.text).toContain('3 finding(s)');
    expect(output.data.note).toContain('not guaranteed safe');
    expect((output.data.summary as { project: { name: string } }).project.name).toBe('fixture-app');
  });

  it('filters by severity threshold and category', async () => {
    const high = await toolScan(cache, { severity: 'high' });
    const findings = high.data.findings as Array<{ severity: string }>;
    expect(findings.every((finding) => ['critical', 'high'].includes(finding.severity))).toBe(true);
    const licenses = await toolScan(cache, { category: 'license' });
    expect((licenses.data.findings as unknown[]).length).toBe(1);
  });

  it('honours the result limit and reports truncation', async () => {
    const output = await toolScan(cache, { limit: 1 });
    expect((output.data.findings as unknown[]).length).toBe(1);
    expect(output.data.truncated).toBe(true);
  });
});

describe('toolFindings', () => {
  it('behaves like toolScan', async () => {
    const output = await toolFindings(cache, {});
    expect(output.text).toContain('finding(s)');
  });
});

describe('toolSecurity', () => {
  it('returns only vulnerability/security findings with their advisory ids', async () => {
    const output = await toolSecurity(cache, {});
    expect(output.data.advisoriesRetrieved).toEqual(['GHSA-test-1111-2222']);
    expect(output.data.advisorySource).toBe('osv.dev');
  });
});

describe('toolGraph', () => {
  it('returns graph statistics when no package is requested', async () => {
    const output = await toolGraph(cache, {});
    expect(output.text).toContain('Graph contains');
    expect((output.data.stats as { totalNodes: number }).totalNodes).toBe(3);
  });

  it('queries a package with paths and dependents', async () => {
    const output = await toolGraph(cache, { package: 'copyleft' });
    const entry = (output.data.entries as Array<{ paths: string[]; dependents: string[] }>)[0]!;
    expect(output.text).toContain('1 version');
    expect(entry.paths[0]).toContain('copyleft');
    expect(entry.dependents).toContain('lodash@4.17.20');
  });

  it('reports a missing package explicitly', async () => {
    const output = await toolGraph(cache, { package: 'not-present' });
    expect(output.data.found).toBe(false);
    expect(output.text).toContain('not present');
  });
});

describe('toolLicenses', () => {
  it('summarizes the license distribution and violations', async () => {
    const output = await toolLicenses(cache, {});
    expect(
      (output.data.distribution as Array<{ license: string }>).map((entry) => entry.license).sort(),
    ).toEqual(['AGPL-3.0', 'MIT']);
    expect((output.data.violations as unknown[]).length).toBe(1);
    expect(output.data.disclaimer).toContain('does not provide legal advice');
  });
});

describe('toolPackage', () => {
  it('returns structured evidence, never a bare boolean verdict', async () => {
    vi.spyOn(RegistryClient.prototype, 'getMetadata').mockResolvedValue({
      name: 'express',
      latest: '4.19.2',
      versions: [{ version: '4.19.2', license: 'MIT', dependencies: { accepts: '~1.3.8' } }],
      time: { created: '2010-01-01T00:00:00.000Z' },
      maintainers: [{ name: 'someone' }],
      repository: 'https://github.com/expressjs/express',
      fromCache: false,
      fetchedAt: '2025-01-01T00:00:00.000Z',
    });
    const output = await toolPackage(cache, { name: 'express', checkDownloads: false });
    expect(output.data.exists).toBe(true);
    expect(output.data.verdict).not.toContain('safe: true');
    expect(output.data.verdict).toContain('does not return a boolean');
    expect('safe' in output.data).toBe(false);
    expect(output.data.typosquat).toBeNull();
  });

  it('flags a typosquat candidate while remaining evidence-based', async () => {
    vi.spyOn(RegistryClient.prototype, 'getMetadata').mockResolvedValue({
      name: 'expreess',
      latest: '1.0.0',
      versions: [{ version: '1.0.0', license: 'MIT' }],
      fromCache: false,
      fetchedAt: '2025-01-01T00:00:00.000Z',
    });
    const output = await toolPackage(cache, { name: 'expreess', checkDownloads: false });
    expect((output.data.typosquat as { similarTo: string }).similarTo).toBe('express');
  });

  it('reports a missing package as unknown rather than safe', async () => {
    vi.spyOn(RegistryClient.prototype, 'getMetadata').mockResolvedValue(undefined);
    const output = await toolPackage(cache, { name: 'definitely-not-real-xyz', checkDownloads: false });
    expect(output.data.exists).toBe(false);
    expect(output.data.note).toContain('rather than "safe"');
  });

  it('rejects an unsafe package name before any network call', async () => {
    const spy = vi.spyOn(RegistryClient.prototype, 'getMetadata');
    await expect(toolPackage(cache, { name: '../../etc/passwd' })).rejects.toThrow();
    expect(spy).not.toHaveBeenCalled();
  });
});

describe('toolUpgradePlan', () => {
  it('orders upgrades and flags breaking changes', async () => {
    const output = await toolUpgradePlan(cache, {});
    expect(output.data.caveat).toContain('does not execute upgrades');
    expect((output.data.upgrades as unknown[]).length).toBeGreaterThan(0);
  });
});

describe('toolSbom', () => {
  it('summarizes components and points at the CLI for the full document', async () => {
    const output = await toolSbom(cache, { format: 'spdx' });
    expect(output.data.format).toBe('spdx');
    expect(output.data.hint).toContain('deplyze sbom --format spdx');
  });
});

describe('toolPolicyCheck', () => {
  it('returns the exit code the CI policy would produce', async () => {
    const output = await toolPolicyCheck(cache, {});
    expect(output.data.passed).toBe(false);
    expect(output.data.exitCode).toBe(1);
    expect((output.data.violations as unknown[]).length).toBeGreaterThan(0);
  });
});

describe('toolRemediate', () => {
  it('returns ordered steps without applying them', async () => {
    const output = await toolRemediate(cache, {});
    expect(output.data.note).toContain('never modifies manifests');
    expect((output.data.steps as unknown[]).length).toBeGreaterThan(0);
  });
});

describe('createMcpServer', () => {
  it('builds a connectable server instance', () => {
    const server = createMcpServer();
    expect(typeof server.connect).toBe('function');
  });
});
