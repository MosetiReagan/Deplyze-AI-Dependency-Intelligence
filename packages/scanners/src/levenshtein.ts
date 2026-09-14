/**
 * Damerau-Levenshtein distance with an early-exit threshold.
 *
 * Damerau-Levenshtein (not plain Levenshtein) is required for typosquat
 * detection because adjacent transpositions — `lodahs` for `lodash` — are the
 * single most common typo class and cost 2 under plain Levenshtein.
 */
export function damerauLevenshtein(a: string, b: string, maxDistance = Number.POSITIVE_INFINITY): number {
  if (a === b) return 0;
  if (Math.abs(a.length - b.length) > maxDistance) return maxDistance + 1;
  if (a.length === 0) return b.length;
  if (b.length === 0) return a.length;

  const previousPrevious = new Array<number>(b.length + 1).fill(0);
  let previous = Array.from({ length: b.length + 1 }, (_, i) => i);
  let current = new Array<number>(b.length + 1).fill(0);

  for (let i = 1; i <= a.length; i += 1) {
    current[0] = i;
    let rowMinimum = current[0] as number;
    for (let j = 1; j <= b.length; j += 1) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      let value = Math.min(
        (current[j - 1] as number) + 1,
        (previous[j] as number) + 1,
        (previous[j - 1] as number) + cost,
      );
      if (i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]) {
        value = Math.min(value, (previousPrevious[j - 2] as number) + 1);
      }
      current[j] = value;
      if (value < rowMinimum) rowMinimum = value;
    }
    if (rowMinimum > maxDistance) return maxDistance + 1;
    for (let j = 0; j <= b.length; j += 1) previousPrevious[j] = previous[j] as number;
    const swap = previous;
    previous = current;
    current = swap;
  }
  return previous[b.length] as number;
}

/** Similarity in [0,1] derived from edit distance. */
export function similarity(a: string, b: string): number {
  const longest = Math.max(a.length, b.length);
  if (longest === 0) return 1;
  return 1 - damerauLevenshtein(a, b, longest) / longest;
}

/** Split an npm name into its scope (if any) and base name. */
export function splitPackageName(name: string): { scope?: string; base: string } {
  if (name.startsWith('@')) {
    const slash = name.indexOf('/');
    if (slash === -1) return { base: name };
    return { scope: name.slice(0, slash), base: name.slice(slash + 1) };
  }
  return { base: name };
}
