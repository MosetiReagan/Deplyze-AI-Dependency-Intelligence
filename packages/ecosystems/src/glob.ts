/**
 * Minimal glob matcher for workspace patterns and ignore lists.
 *
 * Supports the subset actually used by package managers and Deplyze config:
 *   `*`  — any characters except `/`
 *   `**` — any characters including `/`
 *   `?`  — a single character except `/`
 *   `!`  — negation prefix (handled by the caller)
 *
 * Full glob syntax is intentionally out of scope; unsupported constructs fall
 * back to literal matching rather than silently matching everything.
 */
export function globToRegExp(pattern: string): RegExp {
  let output = '^';
  for (let i = 0; i < pattern.length; i += 1) {
    const char = pattern[i] as string;
    if (char === '*') {
      if (pattern[i + 1] === '*') {
        // `**/` should also match zero directories.
        if (pattern[i + 2] === '/') {
          output += '(?:.*/)?';
          i += 2;
        } else {
          output += '.*';
          i += 1;
        }
      } else {
        output += '[^/]*';
      }
      continue;
    }
    if (char === '?') {
      output += '[^/]';
      continue;
    }
    output += escapeRegExp(char);
  }
  output += '$';
  return new RegExp(output);
}

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

export function matchesGlob(path: string, pattern: string): boolean {
  return globToRegExp(pattern).test(path);
}

/** Evaluate include/exclude patterns in order; later matches win. */
export function matchesAny(path: string, patterns: string[]): boolean {
  let matched = false;
  for (const raw of patterns) {
    if (raw.startsWith('!')) {
      if (matchesGlob(path, raw.slice(1))) matched = false;
    } else if (matchesGlob(path, raw)) {
      matched = true;
    }
  }
  return matched;
}
