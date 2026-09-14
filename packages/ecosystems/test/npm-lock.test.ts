import { describe, expect, it } from 'vitest';
import { DeplyzeError } from '@deplyze/core';
import { npmLockParser } from '../src/index.js';

describe('npmLockParser (lockfileVersion 3)', () => {
  const lock = JSON.stringify({
    name: 'app',
    version: '1.0.0',
    lockfileVersion: 3,
    packages: {
      '': {
        name: 'app',
        version: '1.0.0',
        license: 'MIT',
        dependencies: { lodash: '^4.17.15' },
        devDependencies: { jest: '^29.0.0' },
      },
      'node_modules/lodash': {
        version: '4.17.15',
        resolved: 'https://registry.npmjs.org/lodash/-/lodash-4.17.15.tgz',
        integrity: 'sha512-abc',
        license: 'MIT',
        dependencies: { nested: '~1.0.0' },
      },
      'node_modules/@scope/pkg': { version: '2.0.0', license: 'Apache-2.0' },
      'node_modules/jest': { version: '29.7.0', dev: true, license: 'MIT' },
      'node_modules/nested': { version: '1.0.5', license: 'ISC' },
    },
  });

  it('parses packages, names and versions', () => {
    const parsed = npmLockParser.parse(lock, 'package-lock.json');
    const byName = new Map(parsed.packages.map((pkg) => [pkg.name, pkg]));
    expect(byName.get('lodash')?.version).toBe('4.17.15');
    expect(byName.get('lodash')?.integrity).toBe('sha512-abc');
    expect(byName.get('lodash')?.license).toBe('MIT');
    expect(byName.get('@scope/pkg')?.version).toBe('2.0.0');
    expect(byName.get('jest')?.dev).toBe(true);
  });

  it('records dependency edges and the root importer', () => {
    const parsed = npmLockParser.parse(lock, 'package-lock.json');
    const lodash = parsed.packages.find((pkg) => pkg.name === 'lodash');
    expect(lodash?.dependencies).toEqual({ nested: '~1.0.0' });
    expect(parsed.imports.map((entry) => `${entry.name}:${entry.kind}`).sort()).toEqual([
      'jest:dev',
      'lodash:prod',
    ]);
  });

  it('reports the lockfile version', () => {
    expect(npmLockParser.parse(lock, 'package-lock.json').formatVersion).toBe('3');
  });

  it('rejects invalid JSON', () => {
    expect(() => npmLockParser.parse('{oops', 'package-lock.json')).toThrow(DeplyzeError);
  });

  it('parses the legacy v1 dependency tree', () => {
    const legacy = JSON.stringify({
      name: 'app',
      lockfileVersion: 1,
      dependencies: {
        lodash: { version: '4.17.15', requires: { nested: '^1.0.0' } },
        nested: { version: '1.0.0' },
      },
    });
    const parsed = npmLockParser.parse(legacy, 'package-lock.json');
    expect(parsed.packages.map((pkg) => `${pkg.name}@${pkg.version}`).sort()).toEqual([
      'lodash@4.17.15',
      'nested@1.0.0',
    ]);
    expect(parsed.imports.length).toBe(2);
  });

  it('handles an empty lockfile without throwing', () => {
    const parsed = npmLockParser.parse('{"lockfileVersion":3}', 'package-lock.json');
    expect(parsed.packages).toEqual([]);
    expect(parsed.notes.length).toBeGreaterThan(0);
  });
});
