import { describe, expect, it } from 'vitest';
import { DeplyzeError } from '@deplyze/core';
import { parsePnpmPackageKey, pnpmLockParser } from '../src/index.js';

describe('parsePnpmPackageKey', () => {
  it('parses the v9 name@version form', () => {
    expect(parsePnpmPackageKey('lodash@4.17.21')).toEqual({ name: 'lodash', version: '4.17.21' });
    expect(parsePnpmPackageKey('@scope/name@1.0.0')).toEqual({ name: '@scope/name', version: '1.0.0' });
  });

  it('parses the v5 legacy slash form', () => {
    expect(parsePnpmPackageKey('/lodash/4.17.21')).toEqual({ name: 'lodash', version: '4.17.21' });
    expect(parsePnpmPackageKey('/@scope/name/1.0.0')).toEqual({ name: '@scope/name', version: '1.0.0' });
  });

  it('strips peer-dependency suffixes', () => {
    expect(parsePnpmPackageKey('react-dom@18.2.0(react@18.2.0)')).toEqual({
      name: 'react-dom',
      version: '18.2.0',
    });
    expect(parsePnpmPackageKey('/react-dom/18.2.0_react@18.2.0')).toEqual({
      name: 'react-dom',
      version: '18.2.0',
    });
  });

  it('returns undefined for unusable keys', () => {
    expect(parsePnpmPackageKey('garbage')).toBeUndefined();
    expect(parsePnpmPackageKey('')).toBeUndefined();
  });
});

describe('pnpmLockParser (v9)', () => {
  const lock = `
lockfileVersion: '9.0'

importers:
  .:
    dependencies:
      lodash:
        specifier: ^4.17.21
        version: 4.17.21
    devDependencies:
      vitest:
        specifier: ^2.0.0
        version: 2.1.9
  packages/core:
    dependencies:
      '@scope/util':
        specifier: workspace:*
        version: link:../util

packages:
  lodash@4.17.21:
    resolution: {integrity: sha512-lodash}
  vitest@2.1.9:
    resolution: {integrity: sha512-vitest}
  accepts@1.3.8:
    resolution: {integrity: sha512-accepts}

snapshots:
  lodash@4.17.21: {}
  vitest@2.1.9:
    dependencies:
      accepts: 1.3.8
  accepts@1.3.8: {}
`;

  it('parses packages with resolution metadata', () => {
    const parsed = pnpmLockParser.parse(lock, 'pnpm-lock.yaml');
    const lodash = parsed.packages.find((pkg) => pkg.name === 'lodash');
    expect(lodash?.version).toBe('4.17.21');
    expect(lodash?.integrity).toBe('sha512-lodash');
  });

  it('reads dependency edges from snapshots', () => {
    const parsed = pnpmLockParser.parse(lock, 'pnpm-lock.yaml');
    const vitest = parsed.packages.find((pkg) => pkg.name === 'vitest');
    expect(vitest?.dependencies).toEqual({ accepts: '1.3.8' });
  });

  it('collects importers and skips workspace links', () => {
    const parsed = pnpmLockParser.parse(lock, 'pnpm-lock.yaml');
    expect(parsed.imports.map((entry) => `${entry.importer}:${entry.name}:${entry.kind}`)).toEqual([
      '.:lodash:prod',
      '.:vitest:dev',
      'packages/core:@scope/util:prod',
    ]);
    expect(parsed.imports.find((entry) => entry.name === '@scope/util')?.resolvedVersion).toBeUndefined();
  });

  it('rejects invalid YAML', () => {
    expect(() => pnpmLockParser.parse('a:\n  - b\n :::', 'pnpm-lock.yaml')).toThrow(DeplyzeError);
  });

  it('refuses a lockfile from a future major version', () => {
    expect(() => pnpmLockParser.parse("lockfileVersion: '12.0'", 'pnpm-lock.yaml')).toThrow(DeplyzeError);
  });

  it('parses the v5 legacy layout', () => {
    const legacy = `
lockfileVersion: 5.4
dependencies:
  lodash:
    specifier: ^4.17.21
    version: 4.17.21
packages:
  /lodash/4.17.21:
    resolution: {integrity: sha512-lodash}
    dev: false
`;
    const parsed = pnpmLockParser.parse(legacy, 'pnpm-lock.yaml');
    expect(parsed.packages[0]?.name).toBe('lodash');
    expect(parsed.imports[0]?.name).toBe('lodash');
  });
});
