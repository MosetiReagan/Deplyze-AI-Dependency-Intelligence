import { describe, expect, it } from 'vitest';
import { findUnusedDependencies, unusedScanner, type RegistryMetadata } from '../src/index.js';
import { makeContext, makeNode, makeSourceUsage } from '../../../test/helpers.js';

function nodeFor(name: string, overrides = {}) {
  return makeNode({
    name,
    version: '1.0.0',
    direct: true,
    depth: 1,
    workspace: '.',
    id: `npm:${name}@1.0.0`,
    ...overrides,
  });
}

describe('findUnusedDependencies', () => {
  it('flags a declared-but-unreferenced dependency', () => {
    const context = makeContext({
      nodes: [nodeFor('leftpad')],
      edges: [['root:.', 'npm:leftpad@1.0.0']],
      sourceUsage: makeSourceUsage({ filesScanned: 3 }),
    });
    const results = findUnusedDependencies(context);
    expect(results).toHaveLength(1);
    expect(results[0]?.confidence).toBe('high');
    expect(results[0]?.possiblyDynamic).toBe(false);
  });

  it('does not flag a dependency that is imported', () => {
    const context = makeContext({
      nodes: [nodeFor('lodash')],
      edges: [['root:.', 'npm:lodash@1.0.0']],
      sourceUsage: makeSourceUsage({ imported: new Map([['lodash', ['src/index.ts']]]) }),
    });
    expect(findUnusedDependencies(context)).toEqual([]);
  });

  it('does not flag a dependency whose CLI is invoked in a script', () => {
    const metadata = new Map<string, RegistryMetadata>([
      [
        'esbuild',
        {
          name: 'esbuild',
          versions: [{ version: '1.0.0', bin: { esbuild: 'bin/esbuild' } }],
          fromCache: false,
          fetchedAt: '2025-01-01T00:00:00.000Z',
        },
      ],
    ]);
    const context = makeContext({
      nodes: [nodeFor('esbuild')],
      edges: [['root:.', 'npm:esbuild@1.0.0']],
      metadata,
      sourceUsage: makeSourceUsage({ scriptCommands: new Set(['esbuild']) }),
    });
    expect(findUnusedDependencies(context)).toEqual([]);
  });

  it('excludes tooling that is almost never imported directly', () => {
    const context = makeContext({
      nodes: [nodeFor('typescript')],
      edges: [['root:.', 'npm:typescript@1.0.0']],
      sourceUsage: makeSourceUsage(),
    });
    expect(findUnusedDependencies(context)).toEqual([]);
  });

  it('lowers confidence when dynamic imports are present', () => {
    const context = makeContext({
      nodes: [nodeFor('leftpad')],
      edges: [['root:.', 'npm:leftpad@1.0.0']],
      sourceUsage: makeSourceUsage({ hasDynamicImports: true }),
    });
    const results = findUnusedDependencies(context);
    expect(results[0]?.confidence).toBe('low');
    expect(results[0]?.possiblyDynamic).toBe(true);
  });

  it('skips nodes without a workspace attribution', () => {
    const context = makeContext({
      nodes: [
        makeNode({ name: 'leftpad', version: '1.0.0', direct: true, depth: 1, id: 'npm:leftpad@1.0.0' }),
      ],
      edges: [['root:.', 'npm:leftpad@1.0.0']],
      sourceUsage: makeSourceUsage(),
    });
    expect(findUnusedDependencies(context)).toEqual([]);
  });

  it('returns nothing when no source scan was performed', () => {
    const context = makeContext({ nodes: [nodeFor('leftpad')], edges: [['root:.', 'npm:leftpad@1.0.0']] });
    expect(findUnusedDependencies(context)).toEqual([]);
  });
});

describe('unusedScanner', () => {
  it('emits a review-only finding that never claims the package is removable', async () => {
    const context = makeContext({
      nodes: [nodeFor('leftpad')],
      edges: [['root:.', 'npm:leftpad@1.0.0']],
      sourceUsage: makeSourceUsage({ filesScanned: 1 }),
    });
    const findings = await unusedScanner.run(context);
    expect(findings[0]?.title).toContain('Likely unused dependency');
    expect(findings[0]?.description).toContain('never removes dependencies automatically');
    expect(findings[0]?.category).toBe('unused');
  });

  it('is disabled by configuration', async () => {
    const context = makeContext({
      nodes: [nodeFor('leftpad')],
      edges: [['root:.', 'npm:leftpad@1.0.0']],
      sourceUsage: makeSourceUsage({ filesScanned: 1 }),
    });
    context.config.unused.enabled = false;
    expect(await unusedScanner.run(context)).toEqual([]);
  });
});
