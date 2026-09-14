import { describe, expect, it } from 'vitest';
import { DeplyzeError } from '@deplyze/core';
import { declarationsOf, licenseOf, parsePackageJson, workspacePatterns } from '../src/index.js';

describe('parsePackageJson', () => {
  it('parses a normal manifest and preserves unknown fields', () => {
    const manifest = parsePackageJson(
      JSON.stringify({ name: 'app', version: '1.0.0', dependencies: { lodash: '^4.0.0' }, custom: { a: 1 } }),
      'package.json',
    );
    expect(manifest.name).toBe('app');
    expect((manifest as Record<string, unknown>).custom).toEqual({ a: 1 });
  });

  it('rejects invalid JSON with an actionable error', () => {
    expect(() => parsePackageJson('{ nope', 'package.json')).toThrow(DeplyzeError);
  });

  it('rejects structurally invalid dependency maps', () => {
    expect(() => parsePackageJson(JSON.stringify({ dependencies: ['lodash'] }), 'package.json')).toThrow(
      DeplyzeError,
    );
  });

  it('accepts an empty object', () => {
    expect(() => parsePackageJson('{}', 'package.json')).not.toThrow();
  });
});

describe('declarationsOf', () => {
  it('collects every dependency kind', () => {
    const manifest = parsePackageJson(
      JSON.stringify({
        dependencies: { a: '1.0.0' },
        devDependencies: { b: '2.0.0' },
        optionalDependencies: { c: '3.0.0' },
        peerDependencies: { d: '4.0.0' },
      }),
      'package.json',
    );
    const declarations = declarationsOf(manifest, 'package.json');
    expect(declarations.map((entry) => `${entry.name}:${entry.kind}`).sort()).toEqual([
      'a:prod',
      'b:dev',
      'c:optional',
      'd:peer',
    ]);
  });
});

describe('workspacePatterns', () => {
  it('supports both array and object forms', () => {
    expect(workspacePatterns(parsePackageJson(JSON.stringify({ workspaces: ['packages/*'] }), 'p'))).toEqual([
      'packages/*',
    ]);
    expect(
      workspacePatterns(parsePackageJson(JSON.stringify({ workspaces: { packages: ['apps/*'] } }), 'p')),
    ).toEqual(['apps/*']);
    expect(workspacePatterns(parsePackageJson('{}', 'p'))).toEqual([]);
  });
});

describe('licenseOf', () => {
  it('reads string, legacy array and object forms', () => {
    expect(licenseOf(parsePackageJson(JSON.stringify({ license: 'MIT' }), 'p'))).toBe('MIT');
    expect(
      licenseOf(
        parsePackageJson(JSON.stringify({ licenses: [{ type: 'MIT' }, { type: 'Apache-2.0' }] }), 'p'),
      ),
    ).toBe('MIT OR Apache-2.0');
    expect(licenseOf(parsePackageJson(JSON.stringify({ license: { type: 'ISC' } }), 'p'))).toBe('ISC');
    expect(licenseOf(parsePackageJson('{}', 'p'))).toBeUndefined();
  });
});
