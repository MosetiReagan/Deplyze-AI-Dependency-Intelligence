import { describe, expect, it } from 'vitest';
import { supplyChainScanner, type RegistryMetadata } from '../src/index.js';
import { makeContext, makeNode } from '../../../test/helpers.js';

function recentMeta(name: string, daysAgo: number): RegistryMetadata {
  const created = new Date(Date.now() - daysAgo * 24 * 60 * 60 * 1000).toISOString();
  return {
    name,
    latest: '1.0.0',
    versions: [{ version: '1.0.0' }],
    time: { created },
    fromCache: false,
    fetchedAt: new Date().toISOString(),
  };
}

describe('supplyChainScanner', () => {
  it('reports a typosquat signal for a direct dependency', async () => {
    const context = makeContext({
      nodes: [makeNode({ name: 'expreess', version: '1.0.0', direct: true, id: 'npm:expreess@1.0.0' })],
      edges: [['root:.', 'npm:expreess@1.0.0']],
    });
    const findings = await supplyChainScanner.run(context);
    const typosquat = findings.find((finding) => finding.source === 'supply-chain/typosquat');
    expect(typosquat?.package).toBe('expreess');
  });

  it('does not flag transitive packages for name similarity (only direct)', async () => {
    const context = makeContext({
      nodes: [makeNode({ name: 'expreess', version: '1.0.0', depth: 2, id: 'npm:expreess@1.0.0' })],
      edges: [['root:.', 'npm:expreess@1.0.0']],
    });
    expect(
      (await supplyChainScanner.run(context)).filter((f) => f.source === 'supply-chain/typosquat'),
    ).toEqual([]);
  });

  it('reports a freshly published direct dependency', async () => {
    const context = makeContext({
      nodes: [
        makeNode({
          name: 'brand-new-package',
          version: '1.0.0',
          direct: true,
          id: 'npm:brand-new-package@1.0.0',
        }),
      ],
      edges: [['root:.', 'npm:brand-new-package@1.0.0']],
      metadata: new Map([['brand-new-package', recentMeta('brand-new-package', 2)]]),
    });
    const finding = (await supplyChainScanner.run(context)).find(
      (entry) => entry.source === 'supply-chain/new-package',
    );
    expect(finding?.severity).toBe('medium');
    expect(finding?.description).toContain('Age alone does not make a package unsafe');
  });

  it('does not report older packages as newly published', async () => {
    const context = makeContext({
      nodes: [makeNode({ name: 'old-package', version: '1.0.0', direct: true, id: 'npm:old-package@1.0.0' })],
      edges: [['root:.', 'npm:old-package@1.0.0']],
      metadata: new Map([['old-package', recentMeta('old-package', 900)]]),
    });
    expect(
      (await supplyChainScanner.run(context)).filter((f) => f.source === 'supply-chain/new-package'),
    ).toEqual([]);
  });

  it('honours the typosquat disable switch', async () => {
    const context = makeContext({
      nodes: [makeNode({ name: 'expreess', version: '1.0.0', direct: true, id: 'npm:expreess@1.0.0' })],
      edges: [['root:.', 'npm:expreess@1.0.0']],
    });
    context.config.supplyChain.typosquat.enabled = false;
    expect(
      (await supplyChainScanner.run(context)).filter((f) => f.source === 'supply-chain/typosquat'),
    ).toEqual([]);
  });
});
