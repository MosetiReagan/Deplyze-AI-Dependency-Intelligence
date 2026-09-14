import { describe, expect, it } from 'vitest';
import { parseJsonc, stripJsonc } from '../src/index.js';

describe('stripJsonc', () => {
  it('removes line and block comments', () => {
    const input = `{
  // a line comment
  "a": 1, /* block */
  "b": 2
}`;
    expect(JSON.parse(stripJsonc(input))).toEqual({ a: 1, b: 2 });
  });

  it('removes trailing commas', () => {
    expect(JSON.parse(stripJsonc('{"a": [1,2,3,], "b": {"c": 1,},}'))).toEqual({ a: [1, 2, 3], b: { c: 1 } });
  });

  it('never strips content inside strings', () => {
    const input = '{"url": "https://example.com/a//b", "note": "/* not a comment */", "x": ","}';
    expect(JSON.parse(stripJsonc(input))).toEqual({
      url: 'https://example.com/a//b',
      note: '/* not a comment */',
      x: ',',
    });
  });

  it('handles escaped quotes inside strings', () => {
    const input = '{"a": "he said \\"/* hi */\\""}';
    expect(JSON.parse(stripJsonc(input))).toEqual({ a: 'he said "/* hi */"' });
  });

  it('still rejects genuinely broken input', () => {
    expect(() => parseJsonc('{ "a": }')).toThrow();
  });
});
