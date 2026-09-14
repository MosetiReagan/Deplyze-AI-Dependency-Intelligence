import { describe, expect, it } from 'vitest';
import {
  collectLicenseIds,
  copyleftFamily,
  evaluateLicenseExpression,
  isUnknownLicense,
  normalizeLicenseId,
  parseLicenseExpression,
} from '../src/index.js';

describe('parseLicenseExpression', () => {
  it('parses identifiers, AND, OR, WITH and +', () => {
    expect(parseLicenseExpression('MIT')).toEqual({ kind: 'license', id: 'MIT', orLater: false });
    expect(collectLicenseIds(parseLicenseExpression('MIT OR Apache-2.0'))).toEqual(['MIT', 'Apache-2.0']);
    expect(collectLicenseIds(parseLicenseExpression('MIT AND Apache-2.0'))).toEqual(['MIT', 'Apache-2.0']);
    expect(collectLicenseIds(parseLicenseExpression('(MIT OR ISC) AND Apache-2.0'))).toEqual([
      'MIT',
      'ISC',
      'Apache-2.0',
    ]);
    expect(parseLicenseExpression('GPL-2.0+')).toEqual({
      kind: 'license',
      id: 'GPL-2.0-only',
      orLater: true,
    });
    const withException = parseLicenseExpression('GPL-2.0 WITH Classpath-exception-2.0');
    expect(withException?.kind).toBe('license');
    expect((withException as { exception?: string }).exception).toBe('Classpath-exception-2.0');
  });

  it('returns undefined for malformed expressions', () => {
    expect(parseLicenseExpression('MIT AND')).toBeUndefined();
    expect(parseLicenseExpression('')).toBeUndefined();
  });
});

describe('evaluateLicenseExpression', () => {
  const allowed = (id: string) => id === 'MIT' || id === 'Apache-2.0';

  it('accepts OR when any branch is acceptable', () => {
    expect(evaluateLicenseExpression(parseLicenseExpression('MIT OR GPL-3.0')!, allowed).acceptable).toBe(
      true,
    );
  });

  it('rejects AND when any branch is unacceptable', () => {
    const result = evaluateLicenseExpression(parseLicenseExpression('MIT AND GPL-3.0')!, allowed);
    expect(result.acceptable).toBe(false);
    expect(result.rejected).toContain('GPL-3.0-only');
  });

  it('explains why an expression was rejected', () => {
    const result = evaluateLicenseExpression(parseLicenseExpression('AGPL-3.0')!, allowed);
    expect(result.reason).toContain('AGPL-3.0');
  });
});

describe('normalizeLicenseId', () => {
  it('maps aliases and canonicalizes SPDX casing', () => {
    expect(normalizeLicenseId('mit license')).toBe('MIT');
    expect(normalizeLicenseId('apache 2.0')).toBe('Apache-2.0');
    expect(normalizeLicenseId('BSD-3-clause')).toBe('BSD-3-Clause');
  });

  it('leaves SEE LICENSE IN and LicenseRef as opaque identifiers', () => {
    expect(normalizeLicenseId('SEE LICENSE IN LICENSE.txt')).toBe('SEE LICENSE IN LICENSE.txt');
    expect(normalizeLicenseId('LicenseRef-Custom')).toBe('LicenseRef-Custom');
  });
});

describe('isUnknownLicense', () => {
  it('treats missing, empty and placeholder licenses as unknown', () => {
    expect(isUnknownLicense(undefined)).toBe(true);
    expect(isUnknownLicense('')).toBe(true);
    expect(isUnknownLicense('UNKNOWN')).toBe(true);
    expect(isUnknownLicense('Proprietary')).toBe(true);
    expect(isUnknownLicense('MIT')).toBe(false);
  });
});

describe('copyleftFamily', () => {
  it('classifies copyleft strength', () => {
    expect(copyleftFamily('AGPL-3.0')).toBe('network');
    expect(copyleftFamily('GPL-3.0')).toBe('strong');
    expect(copyleftFamily('LGPL-2.1')).toBe('weak');
    expect(copyleftFamily('MPL-2.0')).toBe('weak');
    expect(copyleftFamily('MIT')).toBeUndefined();
  });
});
