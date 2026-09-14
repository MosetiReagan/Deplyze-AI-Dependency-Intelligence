import { describe, expect, it } from 'vitest';
import path from 'node:path';
import { DeplyzeError, assertSafePackageName, isPathInside, resolveWithin } from '../src/index.js';

describe('resolveWithin', () => {
  const root = path.resolve('/tmp/project');

  it('resolves nested paths', () => {
    expect(resolveWithin(root, 'packages/a/package.json')).toBe(path.join(root, 'packages/a/package.json'));
  });

  it('rejects traversal escapes', () => {
    expect(() => resolveWithin(root, '../secrets')).toThrow(DeplyzeError);
    expect(() => resolveWithin(root, 'a/../../secrets')).toThrow(DeplyzeError);
    expect(() => resolveWithin(root, '/etc/passwd')).toThrow(DeplyzeError);
  });

  it('accepts the root itself', () => {
    expect(resolveWithin(root, '.')).toBe(root);
  });
});

describe('isPathInside', () => {
  it('distinguishes inside from outside', () => {
    expect(isPathInside('/a/b', '/a/b/c')).toBe(true);
    expect(isPathInside('/a/b', '/a/c')).toBe(false);
  });
});

describe('assertSafePackageName', () => {
  it('accepts valid npm names', () => {
    for (const name of ['lodash', 'left-pad', '@scope/name', 'a.b_c', 'x'.repeat(214)]) {
      expect(() => assertSafePackageName(name)).not.toThrow();
    }
  });

  it('rejects traversal and injection attempts', () => {
    for (const name of ['../evil', 'a/../../b', 'foo\\bar', 'foo\0bar', '', '/absolute', 'a'.repeat(215)]) {
      expect(() => assertSafePackageName(name), name).toThrow(DeplyzeError);
    }
  });

  it('rejects names with shell metacharacters', () => {
    for (const name of ['foo;rm -rf /', 'foo$(whoami)', 'foo`id`', 'foo bar']) {
      expect(() => assertSafePackageName(name), name).toThrow(DeplyzeError);
    }
  });
});
