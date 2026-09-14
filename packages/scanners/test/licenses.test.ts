import { describe, expect, it } from 'vitest';
import type { RegistryMetadata } from '../src/index.js';
import { licenseFindingsFor, resolveLicense } from '../src/index.js';
import { makeNode, makeResult } from '../../../test/helpers.js';

const policy = { allowed: [], denied: [], unknown: 'warn' as const, failOnDenied: true };

function metadataFor(name: string, license: string, version = '1.0.0'): RegistryMetadata {
  return {
    name,
    latest: version,
    versions: [{ version, license }],
    fromCache: false,
    fetchedAt: '2025-01-01T00:00:00.000Z',
  };
}

describe('resolveLicense', () => {
  it('prefers the license recorded in the lockfile', () => {
    const node = makeNode({ name: 'lodash', version: '1.0.0', license: 'MIT' });
    const resolved = resolveLicense(node, metadataFor('lodash', 'ISC'));
    expect(resolved.source).toBe('lockfile');
    expect(resolved.id).toBe('MIT');
  });

  it('falls back to registry metadata when the lockfile has none', () => {
    const node = makeNode({ name: 'lodash', version: '1.0.0' });
    const resolved = resolveLicense(node, metadataFor('lodash', 'Apache-2.0'));
    expect(resolved.source).toBe('registry');
    expect(resolved.ids).toContain('Apache-2.0');
  });

  it('reports unknown when no source provides a license', () => {
    const resolved = resolveLicense(makeNode({ name: 'x', version: '1.0.0' }), undefined);
    expect(resolved.source).toBe('unknown');
    expect(resolved.ids).toEqual([]);
  });
});

describe('licenseFindingsFor', () => {
  const project = makeResult().project;

  it('flags unknown licenses when policy is warn', () => {
    const findings = licenseFindingsFor(
      [makeNode({ name: 'mystery', version: '1.0.0' })],
      new Map(),
      project,
      policy,
    );
    expect(findings).toHaveLength(1);
    expect(findings[0]?.source).toBe('license/unknown');
    expect(findings[0]?.severity).toBe('low');
  });

  it('stays silent about unknown licenses when policy is ignore', () => {
    const findings = licenseFindingsFor(
      [makeNode({ name: 'mystery', version: '1.0.0' })],
      new Map(),
      project,
      { ...policy, unknown: 'ignore' },
    );
    expect(findings).toEqual([]);
  });

  it('reports a denied license as a policy violation', () => {
    const node = makeNode({ name: 'copyleft', version: '1.0.0', license: 'AGPL-3.0' });
    const findings = licenseFindingsFor([node], new Map(), project, {
      ...policy,
      allowed: ['MIT', 'Apache-2.0'],
      denied: ['AGPL-3.0'],
    });
    expect(findings).toHaveLength(1);
    expect(findings[0]?.source).toBe('license/policy');
    expect(findings[0]?.severity).toBe('high');
  });

  it('accepts a dual-licensed package when one branch is allowed', () => {
    const node = makeNode({ name: 'dual', version: '1.0.0', license: 'MIT OR GPL-3.0' });
    const findings = licenseFindingsFor([node], new Map(), project, {
      ...policy,
      allowed: ['MIT'],
      denied: ['GPL-3.0'],
    });
    expect(findings).toEqual([]);
  });

  it('rejects a conjunctive dual license when any branch is denied', () => {
    const node = makeNode({ name: 'both', version: '1.0.0', license: 'MIT AND GPL-3.0' });
    const findings = licenseFindingsFor([node], new Map(), project, {
      ...policy,
      allowed: ['MIT'],
      denied: ['GPL-3.0'],
    });
    expect(findings).toHaveLength(1);
  });

  it('accepts licenses on the allowlist', () => {
    const node = makeNode({ name: 'fine', version: '1.0.0', license: 'MIT' });
    expect(licenseFindingsFor([node], new Map(), project, { ...policy, allowed: ['MIT'] })).toEqual([]);
  });
});
