import { describe, expect, it } from 'vitest';
import { damerauLevenshtein, similarity, splitPackageName } from '../src/index.js';

describe('damerauLevenshtein', () => {
  it('counts a transposition as one edit', () => {
    expect(damerauLevenshtein('lodash', 'lodahs')).toBe(1);
    expect(damerauLevenshtein('express', 'exrpess')).toBe(1);
  });

  it('computes insertions, deletions and substitutions', () => {
    expect(damerauLevenshtein('express', 'expresss')).toBe(1);
    expect(damerauLevenshtein('express', 'expres')).toBe(1);
    expect(damerauLevenshtein('express', 'exprezz')).toBe(2);
    expect(damerauLevenshtein('abc', 'abc')).toBe(0);
  });

  it('short-circuits once the distance exceeds the threshold', () => {
    expect(damerauLevenshtein('completely-different', 'xyz', 1)).toBeGreaterThan(1);
  });
});

describe('similarity', () => {
  it('returns 1 for identical strings and decays with distance', () => {
    expect(similarity('lodash', 'lodash')).toBe(1);
    expect(similarity('express', 'expreess')).toBeGreaterThan(0.8);
    expect(similarity('express', 'unrelated')).toBeLessThan(0.5);
  });
});

describe('splitPackageName', () => {
  it('splits scoped names', () => {
    expect(splitPackageName('@scope/thing')).toEqual({ scope: '@scope', base: 'thing' });
    expect(splitPackageName('lodash')).toEqual({ base: 'lodash' });
  });
});
