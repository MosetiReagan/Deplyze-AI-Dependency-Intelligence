import { readFile, stat } from 'node:fs/promises';
import path from 'node:path';
import { DeplyzeError, ErrorCode } from './errors.js';

/** Files larger than this are refused rather than read into memory. */
export const MAX_FILE_BYTES = 64 * 1024 * 1024;

/**
 * Resolve `relative` inside `root`, refusing to escape it.
 *
 * Guards DS1: path traversal. Callers pass untrusted-ish input (lockfile
 * `resolved` URLs, config paths, CLI arguments) through this helper.
 */
export function resolveWithin(root: string, relative: string): string {
  const resolvedRoot = path.resolve(root);
  const target = path.resolve(resolvedRoot, relative);
  const relativeToRoot = path.relative(resolvedRoot, target);
  if (relativeToRoot.startsWith('..') || path.isAbsolute(relativeToRoot)) {
    throw new DeplyzeError(
      ErrorCode.DEPLYZE_E_CONFIG,
      `Refusing to access a path outside the project root: ${relative}`,
      {
        hint: 'Ensure all configured paths are relative to the project root.',
      },
    );
  }
  return target;
}

export function isPathInside(root: string, candidate: string): boolean {
  const relative = path.relative(path.resolve(root), path.resolve(candidate));
  return relative === '' || (!relative.startsWith('..') && !path.isAbsolute(relative));
}

export async function readFileSafe(filePath: string, maxBytes = MAX_FILE_BYTES): Promise<string> {
  const info = await stat(filePath);
  if (!info.isFile()) {
    throw new DeplyzeError(ErrorCode.DEPLYZE_E_CONFIG, `Not a regular file: ${filePath}`);
  }
  if (info.size > maxBytes) {
    throw new DeplyzeError(
      ErrorCode.DEPLYZE_E_OVERSIZED_FILE,
      `Refusing to read ${path.basename(filePath)} (${(info.size / 1024 / 1024).toFixed(1)} MiB) which exceeds the ${(
        maxBytes /
        1024 /
        1024
      ).toFixed(0)} MiB limit.`,
      { hint: 'Increase `scan.maxFileBytes` in your Deplyze configuration if this is expected.' },
    );
  }
  return readFile(filePath, 'utf8');
}

export async function fileExists(filePath: string): Promise<boolean> {
  try {
    const info = await stat(filePath);
    return info.isFile();
  } catch {
    return false;
  }
}

/**
 * Reject package names that could be used for path traversal or injection.
 * npm allows scoped names (`@scope/name`), dots, hyphens, underscores.
 */
export function assertSafePackageName(name: string): void {
  if (name.length === 0 || name.length > 214) {
    throw new DeplyzeError(ErrorCode.DEPLYZE_E_USAGE, `Invalid package name: "${name}"`);
  }
  if (name.includes('\0') || name.includes('..') || name.startsWith('/') || name.includes('\\')) {
    throw new DeplyzeError(ErrorCode.DEPLYZE_E_USAGE, `Unsafe package name rejected: "${name}"`, {
      hint: 'Package names must not contain path separators, NUL bytes, or `..`.',
    });
  }
  const valid = /^(?:@[a-z0-9-~][a-z0-9-._~]*\/)?[a-z0-9-~][a-z0-9-._~]*$/i;
  if (!valid.test(name)) {
    throw new DeplyzeError(ErrorCode.DEPLYZE_E_USAGE, `Invalid package name: "${name}"`);
  }
}
