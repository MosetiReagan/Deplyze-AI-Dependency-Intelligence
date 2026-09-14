/**
 * Tolerant JSONC parser.
 *
 * Bun's text lockfile and several config formats are JSON with comments and
 * trailing commas. `JSON.parse` rejects both, so we strip them while
 * respecting string literals, then defer to `JSON.parse` for real syntax
 * validation (so genuinely malformed input still fails loudly).
 */
export function parseJsonc(raw: string): unknown {
  return JSON.parse(stripJsonc(raw));
}

export function stripJsonc(raw: string): string {
  let output = '';
  let inString = false;
  let inLineComment = false;
  let inBlockComment = false;
  let escaped = false;

  for (let i = 0; i < raw.length; i += 1) {
    const char = raw[i] as string;
    const next = raw[i + 1];

    if (inLineComment) {
      if (char === '\n') {
        inLineComment = false;
        output += char;
      }
      continue;
    }
    if (inBlockComment) {
      if (char === '*' && next === '/') {
        inBlockComment = false;
        i += 1;
      }
      continue;
    }
    if (inString) {
      output += char;
      if (escaped) {
        escaped = false;
      } else if (char === '\\') {
        escaped = true;
      } else if (char === '"') {
        inString = false;
      }
      continue;
    }
    if (char === '"') {
      inString = true;
      output += char;
      continue;
    }
    if (char === '/' && next === '/') {
      inLineComment = true;
      i += 1;
      continue;
    }
    if (char === '/' && next === '*') {
      inBlockComment = true;
      i += 1;
      continue;
    }
    output += char;
  }
  return removeTrailingCommas(output);
}

function removeTrailingCommas(input: string): string {
  let output = '';
  let inString = false;
  let escaped = false;
  for (let i = 0; i < input.length; i += 1) {
    const char = input[i] as string;
    if (inString) {
      output += char;
      if (escaped) escaped = false;
      else if (char === '\\') escaped = true;
      else if (char === '"') inString = false;
      continue;
    }
    if (char === '"') {
      inString = true;
      output += char;
      continue;
    }
    if (char === ',') {
      let j = i + 1;
      while (j < input.length && /\s/.test(input[j] as string)) j += 1;
      const next = input[j];
      if (next === '}' || next === ']') continue;
    }
    output += char;
  }
  return output;
}
