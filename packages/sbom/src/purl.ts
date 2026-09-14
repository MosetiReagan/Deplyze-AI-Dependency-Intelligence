import type { DependencyNode, Ecosystem } from '@deplyze/core';

/** purl type prefix per ecosystem (https://github.com/package-url/purl-spec). */
const PURL_TYPE: Partial<Record<Ecosystem, string>> = {
  npm: 'npm',
  pypi: 'pypi',
  cargo: 'cargo',
  go: 'golang',
  maven: 'maven',
  nuget: 'nuget',
  composer: 'composer',
  gem: 'gem',
};

export function purlFor(node: Pick<DependencyNode, 'ecosystem' | 'name' | 'version'>): string {
  const type = PURL_TYPE[node.ecosystem] ?? node.ecosystem;
  const encoded = node.ecosystem === 'npm' ? encodeNpmName(node.name) : encodeURIComponent(node.name);
  return `pkg:${type}/${encoded}@${encodeURIComponent(node.version)}`;
}

function encodeNpmName(name: string): string {
  // Scoped names encode the slash but keep the leading `@`.
  if (name.startsWith('@'))
    return `${name.split('/')[0]}/${encodeURIComponent(name.split('/').slice(1).join('/'))}`;
  return encodeURIComponent(name);
}

/** Convert an SRI hash (`sha512-<base64>`) into the hex form SBOMs require. */
export function sriToHex(
  integrity: string,
): { algorithm: 'SHA-256' | 'SHA-384' | 'SHA-512'; hex: string } | undefined {
  const match = integrity.trim().match(/^(sha256|sha384|sha512)-([A-Za-z0-9+/=]+)/);
  if (!match) return undefined;
  const algorithm = `SHA-${match[1]?.replace('sha', '').toUpperCase()}` as 'SHA-256' | 'SHA-384' | 'SHA-512';
  try {
    const hex = Buffer.from(match[2] as string, 'base64').toString('hex');
    if (hex.length === 0) return undefined;
    return { algorithm, hex };
  } catch {
    return undefined;
  }
}
