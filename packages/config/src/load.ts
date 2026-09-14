import { access } from 'node:fs/promises';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { DeplyzeError, ErrorCode, readFileSafe } from '@deplyze/core';
import { parse as parseYaml } from 'yaml';
import { resolveConfig, type ResolvedConfig } from './resolve.js';

export const CONFIG_FILENAMES = [
  '.deplyze.yml',
  '.deplyze.yaml',
  '.deplyze.json',
  'deplyze.config.js',
  'deplyze.config.mjs',
  'deplyze.config.cjs',
  'deplyze.config.ts',
] as const;

async function exists(file: string): Promise<boolean> {
  try {
    await access(file);
    return true;
  } catch {
    return false;
  }
}

export interface LoadConfigOptions {
  /** Explicit config path from the CLI (`--config`). */
  explicitPath?: string;
  /** Skip config-file discovery entirely. */
  skip?: boolean;
}

/**
 * Discover and load `.deplyze.yml` (or another supported format).
 *
 * Executable configs (`deplyze.config.js`/`.ts`) are imported rather than
 * evaluated in the scanner's process only when the user explicitly relies on
 * them; importing a JS config executes user code, which is a documented,
 * opt-in behaviour for config files (never for package metadata).
 */
export async function loadConfig(root: string, options: LoadConfigOptions = {}): Promise<ResolvedConfig> {
  if (options.skip) return resolveConfig({});

  if (options.explicitPath) {
    const absolute = path.resolve(root, options.explicitPath);
    if (!(await exists(absolute))) {
      throw new DeplyzeError(
        ErrorCode.DEPLYZE_E_CONFIG,
        `Configuration file not found: ${options.explicitPath}`,
        {
          hint: 'Pass a path relative to the project root, or omit --config to auto-discover.',
        },
      );
    }
    return loadConfigFile(absolute);
  }

  for (const filename of CONFIG_FILENAMES) {
    const candidate = path.join(root, filename);
    if (await exists(candidate)) {
      return loadConfigFile(candidate);
    }
  }
  return resolveConfig({});
}

export async function loadConfigFile(absolutePath: string): Promise<ResolvedConfig> {
  const extension = path.extname(absolutePath).toLowerCase();
  try {
    if (extension === '.yml' || extension === '.yaml') {
      const raw = await readFileSafe(absolutePath, 4 * 1024 * 1024);
      return resolveConfig(parseYaml(raw), absolutePath);
    }
    if (extension === '.json') {
      const raw = await readFileSafe(absolutePath, 4 * 1024 * 1024);
      return resolveConfig(JSON.parse(raw), absolutePath);
    }
    if (extension === '.js' || extension === '.mjs' || extension === '.cjs' || extension === '.ts') {
      const imported = (await import(pathToFileURL(absolutePath).href)) as { default?: unknown };
      return resolveConfig(imported.default ?? {}, absolutePath);
    }
    throw new DeplyzeError(ErrorCode.DEPLYZE_E_CONFIG, `Unsupported configuration file type: ${extension}`, {
      hint: 'Use .deplyze.yml, .deplyze.json or deplyze.config.{js,mjs,cjs,ts}.',
    });
  } catch (error) {
    if (error instanceof DeplyzeError) throw error;
    throw new DeplyzeError(
      ErrorCode.DEPLYZE_E_CONFIG,
      `Could not load configuration from ${path.basename(absolutePath)}.`,
      {
        hint: 'Check the file for syntax errors, then re-run with --verbose for details.',
        cause: error,
      },
    );
  }
}
