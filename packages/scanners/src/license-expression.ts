/**
 * A small SPDX licence expression parser.
 *
 * Supports the subset that actually appears in npm metadata: identifiers,
 * `AND`, `OR`, `WITH <exception>`, `+`, and parentheses. `LicenseRef-*` and
 * `SEE LICENSE IN ...` are treated as opaque identifiers rather than errors.
 */

export type LicenseNode =
  | { kind: 'license'; id: string; orLater: boolean; exception?: string }
  | { kind: 'and'; left: LicenseNode; right: LicenseNode }
  | { kind: 'or'; left: LicenseNode; right: LicenseNode };

interface Token {
  type: 'id' | 'and' | 'or' | 'with' | 'lparen' | 'rparen' | 'plus';
  value: string;
}

const KEYWORDS: Record<string, Token['type']> = {
  AND: 'and',
  OR: 'or',
  WITH: 'with',
};

function tokenize(input: string): Token[] {
  const tokens: Token[] = [];
  const normalized = input.replace(/\s+/g, ' ').trim();
  let index = 0;
  while (index < normalized.length) {
    const char = normalized[index] as string;
    if (char === ' ') {
      index += 1;
      continue;
    }
    if (char === '(') {
      tokens.push({ type: 'lparen', value: char });
      index += 1;
      continue;
    }
    if (char === ')') {
      tokens.push({ type: 'rparen', value: char });
      index += 1;
      continue;
    }
    if (char === '+') {
      tokens.push({ type: 'plus', value: char });
      index += 1;
      continue;
    }
    let end = index;
    while (end < normalized.length && !/[\s()+]/.test(normalized[end] as string)) end += 1;
    const word = normalized.slice(index, end);
    index = end;
    const keyword = KEYWORDS[word.toUpperCase()];
    if (keyword) tokens.push({ type: keyword, value: word });
    else tokens.push({ type: 'id', value: word });
  }
  return tokens;
}

export function parseLicenseExpression(input: string): LicenseNode | undefined {
  const tokens = tokenize(input);
  if (tokens.length === 0) return undefined;
  let cursor = 0;

  const peek = (): Token | undefined => tokens[cursor];
  const next = (): Token | undefined => tokens[cursor++];

  const parsePrimary = (): LicenseNode | undefined => {
    const token = next();
    if (!token) return undefined;
    if (token.type === 'lparen') {
      const inner = parseOr();
      const closing = next();
      if (!inner || closing?.type !== 'rparen') return undefined;
      return inner;
    }
    if (token.type !== 'id') return undefined;
    let node: LicenseNode = { kind: 'license', id: normalizeLicenseId(token.value), orLater: false };
    let lookahead = peek();
    while (lookahead?.type === 'plus') {
      next();
      node = { ...(node as { kind: 'license'; id: string; orLater: boolean }), orLater: true };
      lookahead = peek();
    }
    if (peek()?.type === 'with') {
      next();
      const exception = next();
      if (exception?.type !== 'id') return undefined;
      node = {
        ...(node as { kind: 'license'; id: string; orLater: boolean }),
        exception: exception.value,
      };
    }
    return node;
  };

  const parseAnd = (): LicenseNode | undefined => {
    let left = parsePrimary();
    if (!left) return undefined;
    while (peek()?.type === 'and') {
      next();
      const right = parsePrimary();
      if (!right) return undefined;
      left = { kind: 'and', left, right };
    }
    return left;
  };

  const parseOr = (): LicenseNode | undefined => {
    let left = parseAnd();
    if (!left) return undefined;
    while (peek()?.type === 'or') {
      next();
      const right = parseAnd();
      if (!right) return undefined;
      left = { kind: 'or', left, right };
    }
    return left;
  };

  const result = parseOr();
  if (cursor !== tokens.length) return undefined;
  return result;
}

/** Collect every licence identifier mentioned in an expression. */
export function collectLicenseIds(node: LicenseNode | undefined): string[] {
  if (!node) return [];
  if (node.kind === 'license') return [node.id];
  return [...collectLicenseIds(node.left), ...collectLicenseIds(node.right)];
}

export interface EvaluationResult {
  acceptable: boolean;
  /** Human-readable justification for the decision. */
  reason: string;
  /** Identifiers that caused a rejection, when any. */
  rejected: string[];
}

/**
 * Evaluate an expression against a predicate.
 *
 * `OR` succeeds when either branch is acceptable (the consumer may choose that
 * option); `AND` requires both. This is why a dual-licensed `MIT OR GPL-3.0`
 * package satisfies an MIT-only policy, while `MIT AND GPL-3.0` does not.
 */
export function evaluateLicenseExpression(
  node: LicenseNode,
  isAcceptable: (id: string) => boolean,
): EvaluationResult {
  if (node.kind === 'license') {
    const ok = isAcceptable(node.id);
    return {
      acceptable: ok,
      reason: ok ? `${node.id} satisfies the policy.` : `${node.id} is not permitted by the policy.`,
      rejected: ok ? [] : [node.id],
    };
  }
  if (node.kind === 'or') {
    const left = evaluateLicenseExpression(node.left, isAcceptable);
    const right = evaluateLicenseExpression(node.right, isAcceptable);
    if (left.acceptable || right.acceptable) {
      return {
        acceptable: true,
        reason: `${left.acceptable ? left.reason : right.reason} The expression offers a compatible option.`,
        rejected: [],
      };
    }
    return {
      acceptable: false,
      reason: `Neither side of the OR expression is permitted (${left.rejected.join(', ')} / ${right.rejected.join(', ')}).`,
      rejected: [...left.rejected, ...right.rejected],
    };
  }
  const left = evaluateLicenseExpression(node.left, isAcceptable);
  const right = evaluateLicenseExpression(node.right, isAcceptable);
  if (left.acceptable && right.acceptable) {
    return { acceptable: true, reason: 'Both sides of the AND expression satisfy the policy.', rejected: [] };
  }
  return {
    acceptable: false,
    reason: `An AND expression requires every licence to be permitted; rejected: ${[...left.rejected, ...right.rejected].join(', ') || 'unknown'}.`,
    rejected: [...left.rejected, ...right.rejected],
  };
}

const ALIASES: Record<string, string> = {
  'apache 2.0': 'Apache-2.0',
  apache2: 'Apache-2.0',
  'apache-2': 'Apache-2.0',
  bsd: 'BSD-3-Clause',
  'bsd-2': 'BSD-2-Clause',
  'bsd-3': 'BSD-3-Clause',
  'gpl-2': 'GPL-2.0-only',
  'gpl-2.0': 'GPL-2.0-only',
  'gpl-2.0+': 'GPL-2.0-or-later',
  'gpl-3': 'GPL-3.0-only',
  'gpl-3.0': 'GPL-3.0-only',
  'gpl-3.0+': 'GPL-3.0-or-later',
  'agpl-3.0': 'AGPL-3.0-only',
  'lgpl-2.1': 'LGPL-2.1-only',
  'lgpl-3.0': 'LGPL-3.0-only',
  'mit license': 'MIT',
  'the mit license': 'MIT',
  'mpl-2': 'MPL-2.0',
  'isc license': 'ISC',
  unlicensed: 'UNLICENSED',
  proprietary: 'UNLICENSED',
};

const CANONICAL_SPDX: Record<string, string> = {
  mit: 'MIT',
  isc: 'ISC',
  unlicense: 'Unlicense',
  wtfpl: 'WTFPL',
  zlib: 'Zlib',
  x11: 'X11',
  'bsd-2-clause': 'BSD-2-Clause',
  'bsd-3-clause': 'BSD-3-Clause',
  'apache-2.0': 'Apache-2.0',
  'mpl-2.0': 'MPL-2.0',
  '0bsd': '0BSD',
  'cc0-1.0': 'CC0-1.0',
  'blueoak-1.0.0': 'BlueOak-1.0.0',
  'artistic-2.0': 'Artistic-2.0',
};

export function normalizeLicenseId(value: string): string {
  const trimmed = value.trim();
  if (trimmed.length === 0) return 'UNKNOWN';
  const sensitive = /^(SEE LICENSE IN|SEE LICENCE IN|LicenseRef-)/i.test(trimmed);
  if (sensitive) return trimmed;
  const alias = ALIASES[trimmed.toLowerCase()];
  if (alias) return alias;
  // Canonical SPDX ids are case-insensitive. Return the canonical spelling
  // (not the caller's casing) so policy comparisons are stable.
  const canonical = CANONICAL_SPDX[trimmed.toLowerCase()];
  if (canonical) return canonical;
  return trimmed;
}

export function isUnknownLicense(value: string | undefined): boolean {
  if (!value) return true;
  const normalized = value.trim().toLowerCase();
  if (normalized.length === 0) return true;
  if (
    ['unknown', 'none', 'n/a', 'na', 'unlicensed', 'proprietary', 'see license in license'].includes(
      normalized,
    )
  ) {
    return true;
  }
  return false;
}

/** Licences that indicate a copyleft obligation, used for reporting context. */
export function copyleftFamily(id: string): 'strong' | 'weak' | 'network' | undefined {
  const upper = id.toUpperCase();
  if (upper.startsWith('AGPL')) return 'network';
  if (upper.startsWith('GPL')) return 'strong';
  if (upper.startsWith('LGPL')) return 'weak';
  if (upper.startsWith('MPL') || upper.startsWith('EPL') || upper.startsWith('CDDL')) return 'weak';
  return undefined;
}
