import { createHash } from 'node:crypto';

/** Deterministic short hash used for stable finding ids. */
export function shortHash(input: string, length = 12): string {
  return createHash('sha256').update(input).digest('hex').slice(0, length);
}

export function sha256(input: string | Uint8Array): string {
  return createHash('sha256').update(input).digest('hex');
}
