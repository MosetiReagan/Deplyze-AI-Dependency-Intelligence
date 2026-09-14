import { z } from 'zod';
import { SEVERITIES } from '@deplyze/core';

const severitySchema = z.enum(SEVERITIES);

export const suppressionSchema = z.object({
  id: z.string().min(1),
  reason: z.string().min(1, 'Suppressions must include a reason.'),
  expires: z.string().optional(),
  package: z.string().optional(),
  createdBy: z.string().optional(),
});

export const scanSchema = z.object({
  ecosystems: z.array(z.string()).default(['npm']),
  include: z.array(z.string()).default([]),
  exclude: z.array(z.string()).default([]),
  maxFileBytes: z
    .number()
    .int()
    .positive()
    .default(64 * 1024 * 1024),
  maxNodes: z.number().int().positive().default(250_000),
  concurrency: z.number().int().positive().max(64).default(8),
  offline: z.boolean().default(false),
  includeDev: z.boolean().default(true),
  cache: z
    .object({
      directory: z.string().default('.deplyze-cache'),
      ttlHours: z.number().nonnegative().default(6),
    })
    .default({}),
  registry: z
    .object({
      enabled: z.boolean().default(true),
      url: z.string().default('https://registry.npmjs.org'),
      concurrency: z.number().int().positive().max(64).default(8),
      maxPackages: z.number().int().positive().default(2000),
      timeoutMs: z.number().int().positive().default(15_000),
    })
    .default({}),
});

export const advisoriesSchema = z
  .object({
    enabled: z.boolean().default(true),
    sources: z.array(z.enum(['osv'])).default(['osv']),
    ttlHours: z.number().nonnegative().default(6),
    timeoutMs: z.number().int().positive().default(20_000),
    allowNetwork: z.boolean().default(true),
  })
  .default({});

export const securitySchema = z
  .object({
    failOn: z.array(severitySchema).default(['critical', 'high']),
    vulnerabilities: z
      .object({
        maxCritical: z.number().int().nonnegative().optional(),
        maxHigh: z.number().int().nonnegative().optional(),
        maxMedium: z.number().int().nonnegative().optional(),
        allowedAdvisories: z.array(z.string()).default([]),
      })
      .default({}),
    deprecated: z.object({ fail: z.boolean().default(false) }).default({}),
    installScripts: z
      .object({
        failOn: z.array(z.enum(['critical', 'high', 'medium', 'low'])).default([]),
        allow: z.array(z.string()).default([]),
      })
      .default({}),
  })
  .default({});

export const licensesSchema = z
  .object({
    allowed: z.array(z.string()).default([]),
    denied: z.array(z.string()).default([]),
    /** What to do with packages whose license could not be determined. */
    unknown: z.enum(['ignore', 'warn', 'fail']).default('warn'),
    failOnDenied: z.boolean().default(true),
  })
  .default({});

export const packagesSchema = z
  .object({
    allowed: z.array(z.string()).default([]),
    denied: z.array(z.string()).default([]),
    /** Skip these when reporting unused dependencies (false-positive control). */
    unusedAllow: z.array(z.string()).default([]),
  })
  .default({});

export const supplyChainSchema = z
  .object({
    typosquat: z
      .object({
        enabled: z.boolean().default(true),
        /** Minimum edit distance before a name is flagged. */
        maxDistance: z.number().int().min(1).max(4).default(2),
        /** Skip names shorter than this to avoid noise. */
        minNameLength: z.number().int().min(3).default(5),
      })
      .default({}),
    /** Flag packages published within this window. */
    newPackageDays: z.number().int().positive().default(30),
    /** Warn when a direct dependency pulls in more than this many packages. */
    maxDependencyFootprint: z.number().int().positive().default(250),
    allowlist: z.array(z.string()).default([]),
  })
  .default({});

export const unusedSchema = z
  .object({
    enabled: z.boolean().default(true),
    entrypoints: z.array(z.string()).default([]),
    /** Treat these as always used (build tooling, CLIs, type packages). */
    ignore: z.array(z.string()).default([]),
  })
  .default({});

export const outdatedSchema = z
  .object({
    enabled: z.boolean().default(true),
    failOnMajor: z.boolean().default(false),
    failOnMinor: z.boolean().default(false),
  })
  .default({});

export const outputSchema = z
  .object({
    format: z.enum(['terminal', 'json', 'markdown', 'sarif', 'html']).default('terminal'),
    color: z.enum(['auto', 'always', 'never']).default('auto'),
    quiet: z.boolean().default(false),
    verbose: z.boolean().default(false),
    reportFile: z.string().optional(),
  })
  .default({});

export const aiSchema = z
  .object({
    enabled: z.boolean().default(false),
    provider: z.enum(['none', 'openai', 'anthropic', 'gemini', 'ollama', 'http']).default('none'),
    model: z.string().default(''),
    baseUrl: z.string().default(''),
    /** Name of the environment variable holding the API key. Never the key itself. */
    apiKeyEnv: z.string().default(''),
    maxTokens: z.number().int().positive().max(32_000).default(1500),
    temperature: z.number().min(0).max(2).default(0.2),
    timeoutMs: z.number().int().positive().default(60_000),
    redact: z.boolean().default(true),
    /** Hard cap on how many findings are serialized into a prompt. */
    maxFindings: z.number().int().positive().default(25),
  })
  .default({});

export const ciSchema = z
  .object({
    format: z.enum(['terminal', 'json', 'markdown', 'sarif']).default('terminal'),
    sarifFile: z.string().default(''),
    failOn: z.array(severitySchema).default([]),
    annotations: z.boolean().default(true),
  })
  .default({});

export const deplyzeConfigSchema = z.object({
  version: z.literal(1).default(1),
  scan: scanSchema.optional(),
  advisories: advisoriesSchema.optional(),
  security: securitySchema.optional(),
  licenses: licensesSchema.optional(),
  packages: packagesSchema.optional(),
  supplyChain: supplyChainSchema.optional(),
  unused: unusedSchema.optional(),
  outdated: outdatedSchema.optional(),
  output: outputSchema.optional(),
  ai: aiSchema.optional(),
  ci: ciSchema.optional(),
  ignore: z.array(suppressionSchema).default([]),
});

export type DeplyzeConfigInput = z.input<typeof deplyzeConfigSchema>;
export type DeplyzeConfig = z.output<typeof deplyzeConfigSchema>;
