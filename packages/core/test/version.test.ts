import { describe, expect, it } from 'vitest';
import {
  bestUpgradeWithinRange,
  classifyLag,
  compareVersions,
  isPrerelease,
  maxVersion,
  normalizeRange,
  parseVersion,
  satisfies,
} from '../src/index.js';

describe('satisfies', () => {
  it('evaluates plain semver ranges', () => {
    expect(satisfies('1.2.3', '>=1.0.0 <2.0.0')).toBe(true);
    expect(satisfies('2.0.0', '>=1.0.0 <2.0.0')).toBe(false);
    expect(satisfies('1.2.3', '^1.0.0')).toBe(true);
    expect(satisfies('1.2.3', '~1.2.0')).toBe(true);
    expect(satisfies('1.3.0', '~1.2.0')).toBe(false);
  });

  it('treats comma-separated ranges as a union', () => {
    expect(satisfies('2.5.0', '>=1.0.0 <2.0.0, >=2.0.0 <3.0.0')).toBe(true);
    expect(satisfies('3.0.0', '>=1.0.0 <2.0.0, >=2.0.0 <3.0.0')).toBe(false);
  });

  it('matches everything for a wildcard or latest', () => {
    expect(satisfies('9.9.9', '*')).toBe(true);
    expect(satisfies('9.9.9', 'latest')).toBe(true);
  });

  it('never throws on malformed ranges', () => {
    expect(satisfies('1.0.0', 'not a range')).toBe(false);
    expect(satisfies('1.0.0', '>=1.0.0 <')).toBe(false);
    expect(satisfies('not-a-version', '>=1.0.0')).toBe(false);
  });

  it('does not match prereleases by default', () => {
    expect(satisfies('2.0.0-beta.1', '>=1.0.0')).toBe(false);
  });
});

describe('classifyLag', () => {
  it('classifies each semver dimension', () => {
    expect(classifyLag('1.2.3', '1.2.3')).toBe('equal');
    expect(classifyLag('1.2.3', '1.2.4')).toBe('patch');
    expect(classifyLag('1.2.3', '1.3.0')).toBe('minor');
    expect(classifyLag('1.2.3', '2.0.0')).toBe('major');
    expect(classifyLag('2.0.0', '1.0.0')).toBe('downgrade');
    expect(classifyLag('nonsense', '1.0.0')).toBe('unknown');
  });
});

describe('compareVersions', () => {
  it('orders versions', () => {
    expect(compareVersions('1.10.0', '1.9.9')).toBeGreaterThan(0);
    expect(compareVersions('2.0.0', '1.9.9')).toBeGreaterThan(0);
    expect(compareVersions('1.0.0', '1.0.0')).toBe(0);
  });
});

describe('maxVersion', () => {
  it('ignores prereleases and invalid versions', () => {
    expect(maxVersion(['1.0.0', '2.0.0-beta.1', '1.5.0', 'bogus'])).toBe('1.5.0');
    expect(maxVersion(['bogus'])).toBeUndefined();
  });
});

describe('bestUpgradeWithinRange', () => {
  it('finds the newest compatible upgrade', () => {
    expect(bestUpgradeWithinRange(['1.0.0', '1.2.0', '1.9.9', '2.0.0'], '1.0.0', '^1.0.0')).toBe('1.9.9');
    expect(bestUpgradeWithinRange(['1.0.0'], '1.0.0', '^1.0.0')).toBeUndefined();
  });
});

describe('normalizeRange', () => {
  it('accepts standard ranges and rejects nonsense', () => {
    expect(normalizeRange('^1.2.3')).toBe('>=1.2.3 <2.0.0-0');
    expect(normalizeRange('latest')).toBe('*');
    expect(normalizeRange('!!!')).toBeUndefined();
  });
});

describe('isPrerelease', () => {
  it('detects prerelease versions', () => {
    expect(isPrerelease('1.0.0-beta.1')).toBe(true);
    expect(isPrerelease('1.0.0')).toBe(false);
  });
});

describe('parseVersion', () => {
  it('parses loose versions', () => {
    expect(parseVersion('v1.2.3')?.major).toBe(1);
    expect(parseVersion('nope')).toBeNull();
  });
});
