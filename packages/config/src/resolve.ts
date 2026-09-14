import { DeplyzeError, ErrorCode } from '@deplyze/core';
import { z } from 'zod';
import {
  advisoriesSchema,
  aiSchema,
  ciSchema,
  deplyzeConfigSchema,
  licensesSchema,
  outdatedSchema,
  outputSchema,
  packagesSchema,
  scanSchema,
  securitySchema,
  supplyChainSchema,
  unusedSchema,
} from './schema.js';

export interface ConfigWarning {
  code: string;
  message: string;
  path?: string;
}

export interface ResolvedSuppression {
  id: string;
  reason: string;
  expires?: string;
  package?: string;
  createdBy?: string;
}

export interface ResolvedConfig {
  version: 1;
  scan: z.output<typeof scanSchema>;
  advisories: z.output<typeof advisoriesSchema>;
  security: z.output<typeof securitySchema>;
  licenses: z.output<typeof licensesSchema>;
  packages: z.output<typeof packagesSchema>;
  supplyChain: z.output<typeof supplyChainSchema>;
  unused: z.output<typeof unusedSchema>;
  outdated: z.output<typeof outdatedSchema>;
  output: z.output<typeof outputSchema>;
  ai: z.output<typeof aiSchema>;
  ci: z.output<typeof ciSchema>;
  ignore: ResolvedSuppression[];
  /** Absolute path of the config file that produced this configuration. */
  configPath?: string;
  /** Non-fatal problems detected while interpreting the configuration. */
  warnings: ConfigWarning[];
}

export const defaultConfig = (): ResolvedConfig => ({
  version: 1,
  scan: scanSchema.parse({}),
  advisories: advisoriesSchema.parse({}),
  security: securitySchema.parse({}),
  licenses: licensesSchema.parse({}),
  packages: packagesSchema.parse({}),
  supplyChain: supplyChainSchema.parse({}),
  unused: unusedSchema.parse({}),
  outdated: outdatedSchema.parse({}),
  output: outputSchema.parse({}),
  ai: aiSchema.parse({}),
  ci: ciSchema.parse({}),
  ignore: [],
  warnings: [],
});

/**
 * Validate and normalize raw configuration data.
 *
 * Unknown top-level keys are rejected with a hint rather than ignored, because
 * a silently-ignored `security:` block is a security problem: the user believes
 * a policy is enforced when it is not.
 */
export function resolveConfig(raw: unknown, configPath?: string): ResolvedConfig {
  const known = new Set(Object.keys(defaultConfig()));
  const warnings: ConfigWarning[] = [];

  if (raw !== null && typeof raw === 'object' && !Array.isArray(raw)) {
    for (const key of Object.keys(raw as Record<string, unknown>)) {
      if (!known.has(key)) {
        warnings.push({
          code: 'config.unknown-key',
          message: `Unknown configuration key "${key}" was ignored.`,
          ...(configPath ? { path: configPath } : {}),
        });
      }
    }
  }

  const parsed = deplyzeConfigSchema.safeParse(raw ?? {});
  if (!parsed.success) {
    const issue = parsed.error.issues[0];
    const where = issue?.path.join('.') || '<root>';
    throw new DeplyzeError(
      ErrorCode.DEPLYZE_E_CONFIG,
      `Invalid Deplyze configuration at ${where}: ${issue?.message ?? 'unknown error'}`,
      {
        hint: configPath
          ? `Fix ${configPath} and re-run Deplyze.`
          : 'Fix the configuration and re-run Deplyze.',
      },
    );
  }
  const data = parsed.data;

  const config: ResolvedConfig = {
    version: 1,
    scan: scanSchema.parse(data.scan ?? {}),
    advisories: advisoriesSchema.parse(data.advisories ?? {}),
    security: securitySchema.parse(data.security ?? {}),
    licenses: licensesSchema.parse(data.licenses ?? {}),
    packages: packagesSchema.parse(data.packages ?? {}),
    supplyChain: supplyChainSchema.parse(data.supplyChain ?? {}),
    unused: unusedSchema.parse(data.unused ?? {}),
    outdated: outdatedSchema.parse(data.outdated ?? {}),
    output: outputSchema.parse(data.output ?? {}),
    ai: aiSchema.parse(data.ai ?? {}),
    ci: ciSchema.parse(data.ci ?? {}),
    ignore: (data.ignore ?? []).map((entry) => {
      const suppression: ResolvedSuppression = { id: entry.id, reason: entry.reason };
      if (entry.expires) suppression.expires = entry.expires;
      if (entry.package) suppression.package = entry.package;
      if (entry.createdBy) suppression.createdBy = entry.createdBy;
      return suppression;
    }),
    warnings,
  };
  if (configPath) config.configPath = configPath;

  if (config.scan.offline) config.advisories.allowNetwork = false;
  if (config.scan.ecosystems.length > 0) {
    const unsupported = config.scan.ecosystems.filter((ecosystem) => ecosystem !== 'npm');
    if (unsupported.length > 0) {
      warnings.push({
        code: 'config.unsupported-ecosystem',
        message: `Ecosystem(s) not yet supported and ignored: ${unsupported.join(', ')}.`,
      });
    }
  }
  if (config.ai.enabled && config.ai.provider === 'none') {
    warnings.push({
      code: 'config.ai-no-provider',
      message:
        'AI features are enabled but no provider is configured; AI commands will fail until one is set.',
    });
  }
  return config;
}
