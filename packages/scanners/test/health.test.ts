import { describe, expect, it } from 'vitest';
import { healthScanner, type RegistryMetadata } from '../src/index.js';
import { makeContext, makeNode } from '../../../test/helpers.js';

function meta(name: string, options: Partial<RegistryMetadata> = {}): RegistryMetadata {
  return {
    name,
    versions: [],
    fromCache: false,
    fetchedAt: '2025-01-01T00:00:00.000Z',
    ...options,
  };
}

describe('healthScanner', () => {
  it('reports deprecated packages with the registry notice as evidence', async () => {
    const context = makeContext({
      nodes: [makeNode({ name: 'request', version: '2.88.2', direct: true, id: 'npm:request@2.88.2' })],
      edges: [['root:.', 'npm:request@2.88.2']],
      metadata: new Map([
        [
          'request',
          meta('request', {
            latest: '2.88.2',
            versions: [{ version: '2.88.2', deprecated: 'request is deprecated' }],
          }),
        ],
      ]),
    });
    const findings = await healthScanner.run(context);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.source).toBe('maintenance/deprecated');
    expect(findings[0]?.severity).toBe('medium');
    expect(findings[0]?.evidence[0]?.message).toContain('request is deprecated');
  });

  it('reports a stale release cadence for a direct dependency', async () => {
    const context = makeContext({
      nodes: [makeNode({ name: 'quiet', version: '1.0.0', direct: true, id: 'npm:quiet@1.0.0' })],
      edges: [['root:.', 'npm:quiet@1.0.0']],
      metadata: new Map([
        [
          'quiet',
          meta('quiet', {
            latest: '1.0.0',
            maintainers: [{ name: 'a' }],
            time: { '1.0.0': '2020-01-01T00:00:00Z' },
          }),
        ],
      ]),
    });
    const findings = await healthScanner.run(context);
    expect(findings[0]?.source).toBe('maintenance/stale');
    expect(findings[0]?.description).toContain('not by itself a security problem');
  });

  it('does not report staleness for transitive dependencies', async () => {
    const context = makeContext({
      nodes: [makeNode({ name: 'quiet', version: '1.0.0', depth: 2, id: 'npm:quiet@1.0.0' })],
      edges: [['root:.', 'npm:quiet@1.0.0']],
      metadata: new Map([
        ['quiet', meta('quiet', { latest: '1.0.0', time: { '1.0.0': '2010-01-01T00:00:00Z' } })],
      ]),
    });
    expect(await healthScanner.run(context)).toEqual([]);
  });

  it('stays silent when there is no registry evidence', async () => {
    const context = makeContext({
      nodes: [makeNode({ name: 'unknown', version: '1.0.0', direct: true, id: 'npm:unknown@1.0.0' })],
      edges: [['root:.', 'npm:unknown@1.0.0']],
    });
    expect(await healthScanner.run(context)).toEqual([]);
  });
});
