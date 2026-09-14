import path from 'node:path';
import { Logger, type LogLevel } from '@deplyze/core';
import { loadConfig, type ResolvedConfig } from '@deplyze/config';

export interface GlobalFlags {
  path?: string;
  config?: string;
  verbose?: boolean;
  debug?: boolean;
  quiet?: boolean;
  offline?: boolean;
  network?: boolean;
  color?: string;
  format?: string;
  json?: boolean;
}

export interface CommandContext {
  root: string;
  config: ResolvedConfig;
  logger: Logger;
  flags: GlobalFlags;
  /** Colour mode resolved from flags and config. */
  colorMode: 'auto' | 'always' | 'never';
}

/**
 * Build the shared context for a command: resolved project root, validated
 * configuration and a logger whose level reflects the global verbosity flags.
 */
export async function createContext(flags: GlobalFlags): Promise<CommandContext> {
  const root = path.resolve(flags.path ?? process.cwd());
  const level: LogLevel = flags.debug ? 'debug' : flags.verbose ? 'info' : flags.quiet ? 'silent' : 'warn';
  const logger = new Logger({ level, timestamps: flags.debug === true, json: false });

  let config = await loadConfig(root, flags.config ? { explicitPath: flags.config } : {});

  if (flags.offline) {
    config = {
      ...config,
      scan: { ...config.scan, offline: true },
      advisories: { ...config.advisories, allowNetwork: false },
    };
  }
  if (flags.network === false) {
    config = {
      ...config,
      scan: { ...config.scan, registry: { ...config.scan.registry, enabled: false } },
      advisories: { ...config.advisories, allowNetwork: false },
    };
  }
  if (flags.quiet) config = { ...config, output: { ...config.output, quiet: true } };

  const colorMode =
    flags.color === 'always' || flags.color === 'never' || flags.color === 'auto'
      ? (flags.color as 'auto' | 'always' | 'never')
      : config.output.color;

  for (const warning of config.warnings) logger.warn(warning.message);

  return { root, config, logger, flags, colorMode };
}
