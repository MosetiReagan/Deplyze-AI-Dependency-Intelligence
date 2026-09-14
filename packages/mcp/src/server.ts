import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { z } from 'zod';
import { DeplyzeError, isDeplyzeError, Logger } from '@deplyze/core';
import { ScanCache } from './cache.js';
import {
  toolFindings,
  toolGraph,
  toolLicenses,
  toolPackage,
  toolPolicyCheck,
  toolRemediate,
  toolSbom,
  toolScan,
  toolSecurity,
  toolUpgradePlan,
  type ToolResult,
} from './tools.js';

export const SERVER_NAME = 'deplyze';
export const SERVER_VERSION = '0.1.0';

const pathField = z
  .string()
  .optional()
  .describe('Absolute path to the project root. Defaults to the server process working directory.');
const severityField = z
  .enum(['critical', 'high', 'medium', 'low', 'info'])
  .optional()
  .describe('Only return findings at or above this severity.');
const categoryField = z
  .enum([
    'vulnerability',
    'security',
    'supply-chain',
    'maintenance',
    'license',
    'outdated',
    'unused',
    'duplicate',
    'configuration',
    'compatibility',
  ])
  .optional()
  .describe('Only return findings in this category.');

/** Convert a tool handler result into an MCP CallToolResult. */
function toMcpResult(result: ToolResult): {
  content: Array<{ type: 'text'; text: string }>;
  structuredContent: Record<string, unknown>;
  isError?: boolean;
} {
  return {
    content: [{ type: 'text', text: result.text }],
    structuredContent: result.data,
    ...(result.isError ? { isError: true } : {}),
  };
}

function toErrorResult(error: unknown): {
  content: Array<{ type: 'text'; text: string }>;
  isError: true;
} {
  const message = isDeplyzeError(error)
    ? `${error.message}${error.hint ? `\n\nTry: ${error.hint}` : ''}\n\nCode: ${error.code}`
    : error instanceof Error
      ? error.message
      : String(error);
  return { content: [{ type: 'text', text: `Deplyze error: ${message}` }], isError: true };
}

export interface McpServerOptions {
  logger?: Logger;
  defaultPath?: string;
}

/**
 * Build the Deplyze MCP server.
 *
 * Every tool returns structured evidence. No tool returns a bare
 * `safe: true/false` verdict, because a boolean would hide the uncertainty that
 * dependency data inherently contains.
 */
export function createMcpServer(options: McpServerOptions = {}): McpServer {
  const logger = options.logger ?? new Logger({ level: 'silent' });
  const cache = new ScanCache(logger);
  const server = new McpServer(
    { name: SERVER_NAME, version: SERVER_VERSION, title: 'Deplyze — AI Dependency Intelligence' },
    {
      instructions:
        "Deplyze analyses a project's dependency graph for vulnerabilities, supply-chain risk, license policy, " +
        'outdated packages, duplicates and unused dependencies. Tools return evidence, confidence and remediation ' +
        'rather than boolean verdicts. Prefer calling deplyze_scan first, then query the narrower tools.',
    },
  );

  const wrap = <T>(handler: (args: T) => Promise<ToolResult>) => {
    return async (args: T) => {
      try {
        return toMcpResult(await handler(args));
      } catch (error) {
        logger.debug('MCP tool failed', { error: String(error) });
        return toErrorResult(error);
      }
    };
  };

  server.registerTool(
    'deplyze_scan',
    {
      title: 'Scan project dependencies',
      description:
        'Run a full dependency intelligence scan: vulnerabilities, licenses, outdated packages, duplicates, unused ' +
        'dependencies and supply-chain signals. Returns structured findings with evidence and confidence.',
      inputSchema: {
        path: pathField,
        severity: severityField,
        category: categoryField,
        limit: z
          .number()
          .int()
          .min(1)
          .max(500)
          .optional()
          .describe('Maximum findings to return (default 50).'),
      },
      annotations: { readOnlyHint: true, openWorldHint: true },
    },
    wrap((args: { path?: string; severity?: string; category?: string; limit?: number }) =>
      toolScan(cache, args),
    ),
  );

  server.registerTool(
    'deplyze_findings',
    {
      title: 'List findings',
      description: 'Return findings from a scan, optionally filtered by severity or category.',
      inputSchema: {
        path: pathField,
        severity: severityField,
        category: categoryField,
        limit: z.number().int().min(1).max(500).optional(),
      },
      annotations: { readOnlyHint: true, openWorldHint: true },
    },
    wrap((args: { path?: string; severity?: string; category?: string; limit?: number }) =>
      toolFindings(cache, args),
    ),
  );

  server.registerTool(
    'deplyze_security',
    {
      title: 'Security findings',
      description:
        'Return vulnerability findings sourced from the OSV advisory database, including dependency paths.',
      inputSchema: { path: pathField },
      annotations: { readOnlyHint: true, openWorldHint: true },
    },
    wrap((args: { path?: string }) => toolSecurity(cache, args)),
  );

  server.registerTool(
    'deplyze_dependency_graph',
    {
      title: 'Query the dependency graph',
      description:
        'Inspect the resolved dependency graph. Without a package name it returns graph statistics and duplicates; ' +
        'with a package name it returns versions, dependency paths, dependents and dependencies.',
      inputSchema: {
        path: pathField,
        package: z.string().optional().describe('Package name to query, e.g. "lodash" or "@scope/name".'),
        direction: z.enum(['dependents', 'dependencies', 'both']).optional(),
        limit: z.number().int().min(1).max(200).optional(),
      },
      annotations: { readOnlyHint: true },
    },
    wrap(
      (args: {
        path?: string;
        package?: string;
        direction?: 'dependents' | 'dependencies' | 'both';
        limit?: number;
      }) => toolGraph(cache, args),
    ),
  );

  server.registerTool(
    'deplyze_licenses',
    {
      title: 'License analysis',
      description:
        'Report the license distribution and any license policy violations across resolved packages.',
      inputSchema: { path: pathField },
      annotations: { readOnlyHint: true },
    },
    wrap((args: { path?: string }) => toolLicenses(cache, args)),
  );

  server.registerTool(
    'deplyze_package',
    {
      title: 'Evaluate a package before installing',
      description:
        'Answer "is this package safe to install?" with evidence: existence, publish age, license, deprecation, ' +
        'maintainers, download count, install scripts, dependency footprint and typosquat similarity. Never returns a ' +
        'bare boolean verdict.',
      inputSchema: {
        name: z.string().describe('npm package name, e.g. "express" or "@scope/name".'),
        version: z
          .string()
          .optional()
          .describe('Specific version to evaluate. Defaults to the latest release.'),
        checkDownloads: z
          .boolean()
          .optional()
          .describe('Query weekly download counts (one extra network request).'),
      },
      annotations: { readOnlyHint: true, openWorldHint: true },
    },
    wrap((args: { name: string; version?: string; checkDownloads?: boolean }) => toolPackage(cache, args)),
  );

  server.registerTool(
    'deplyze_upgrade_plan',
    {
      title: 'Upgrade plan',
      description:
        'Produce an ordered upgrade plan derived from security fixes and version drift, with breaking-change flags.',
      inputSchema: { path: pathField },
      annotations: { readOnlyHint: true },
    },
    wrap((args: { path?: string }) => toolUpgradePlan(cache, args)),
  );

  server.registerTool(
    'deplyze_remediate',
    {
      title: 'Remediation steps',
      description:
        'Return concrete, ordered remediation steps for every actionable finding. Deplyze never applies them.',
      inputSchema: { path: pathField },
      annotations: { readOnlyHint: true },
    },
    wrap((args: { path?: string }) => toolRemediate(cache, args)),
  );

  server.registerTool(
    'deplyze_sbom',
    {
      title: 'SBOM summary',
      description: 'Summarize the software bill of materials that Deplyze can generate (CycloneDX or SPDX).',
      inputSchema: { path: pathField, format: z.enum(['cyclonedx', 'spdx']).optional() },
      annotations: { readOnlyHint: true },
    },
    wrap((args: { path?: string; format?: 'cyclonedx' | 'spdx' }) => toolSbom(cache, args)),
  );

  server.registerTool(
    'deplyze_policy_check',
    {
      title: 'Policy check',
      description:
        'Evaluate the configured CI policy (severity thresholds, license denials, denied packages) and return the exit code it would produce.',
      inputSchema: { path: pathField },
      annotations: { readOnlyHint: true },
    },
    wrap((args: { path?: string }) => toolPolicyCheck(cache, args)),
  );

  void DeplyzeError;
  return server;
}

/** Start the server over stdio. Resolves when the transport closes. */
export async function startStdioServer(options: McpServerOptions = {}): Promise<void> {
  const server = createMcpServer(options);
  const transport = new StdioServerTransport();
  await server.connect(transport);
}
