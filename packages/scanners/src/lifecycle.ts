import { createFinding, type Evidence, type Finding } from '@deplyze/core';
import type { RegistryMetadata } from './registry.js';
import type { ScanContext, Scanner } from './types.js';
import { dependencyPaths } from './paths.js';

/** Scripts that run during install or publish — the supply-chain-sensitive set. */
export const LIFECYCLE_SCRIPTS = [
  'preinstall',
  'install',
  'postinstall',
  'prepare',
  'prepublish',
  'prepublishOnly',
] as const;

const SUSPICIOUS_PATTERNS: Array<{ label: string; regex: RegExp }> = [
  {
    label: 'pipes a network download straight into a shell',
    regex: /\b(curl|wget)\b[^|]*\|\s*(sh|bash|zsh|node|python)/i,
  },
  { label: 'decodes base64 and evaluates it', regex: /base64\s+(-d|--decode)[^|]*\|\s*(sh|bash|node)/i },
  { label: 'invokes eval or Function on dynamic content', regex: /\b(eval|new\s+Function)\s*\(/ },
  { label: 'spawns a child process', regex: /\bchild_process\b|\bexecSync\s*\(|\bspawnSync\s*\(/ },
  {
    label: 'reads environment variables that commonly hold secrets',
    regex: /\b(process\.env\.[A-Z0-9_]*(TOKEN|SECRET|KEY|PASSWORD|AUTH)[A-Z0-9_]*)/,
  },
  {
    label: 'writes to the user home or system directories',
    regex: /(os\.homedir\(\)|\/etc\/|\.ssh\/|\.aws\/)/,
  },
  { label: 'posts data to an external host', regex: /\b(fetch|https?\.request|axios)\s*\([^)]*https?:\/\// },
  {
    label: 'obfuscated hex/unicode escape sequence payload',
    regex: /(\\x[0-9a-f]{2}){8,}|(\\u[0-9a-f]{4}){8,}/i,
  },
];

export interface LifecycleScriptRecord {
  package: string;
  version: string;
  script: string;
  command: string;
  suspicious: string[];
  direct: boolean;
}

export function collectLifecycleScripts(
  context: ScanContext,
  metadata: Map<string, RegistryMetadata>,
  options: { maxPackages?: number } = {},
): LifecycleScriptRecord[] {
  const records: LifecycleScriptRecord[] = [];
  const maxPackages = options.maxPackages ?? 3000;
  let inspected = 0;

  const nodes = [...context.graph.allNodes()]
    .filter((node) => node.depth > 0)
    .sort((a, b) => a.depth - b.depth);

  for (const node of nodes) {
    if (inspected >= maxPackages) break;
    inspected += 1;
    const entry = metadata.get(node.name)?.versions.find((version) => version.version === node.version);
    const scripts = entry?.scripts ?? node.scripts;
    if (!scripts) continue;
    for (const script of LIFECYCLE_SCRIPTS) {
      const command = scripts[script];
      if (!command) continue;
      const suspicious = SUSPICIOUS_PATTERNS.filter((pattern) => pattern.regex.test(command)).map(
        (pattern) => pattern.label,
      );
      records.push({
        package: node.name,
        version: node.version,
        script,
        command,
        suspicious,
        direct: node.direct,
      });
    }
  }
  return records;
}

export function lifecycleFindings(records: LifecycleScriptRecord[], context: ScanContext): Finding[] {
  const findings: Finding[] = [];
  const allow = new Set(context.config.security.installScripts.allow);

  for (const record of records) {
    if (allow.has(record.package)) continue;
    const hasSuspicious = record.suspicious.length > 0;
    const isInstallHook =
      record.script === 'preinstall' || record.script === 'install' || record.script === 'postinstall';
    if (!hasSuspicious && !isInstallHook) continue;
    if (record.script === 'prepare' && record.direct === false) continue;

    const severity = hasSuspicious ? (isInstallHook ? 'high' : 'medium') : record.direct ? 'low' : 'info';
    const label = hasSuspicious ? 'Suspicious package characteristics' : 'Lifecycle install script';

    const node = context.graph.getNode(`${record.package}`) ?? undefined;
    void node;
    const targetNode = [...context.graph.allNodes()].find(
      (candidate) => candidate.name === record.package && candidate.version === record.version,
    );
    const paths = targetNode ? dependencyPaths(context.graph, targetNode.id, 2) : [];

    const evidence: Evidence[] = [
      {
        kind: 'lifecycle-script',
        message: `${record.package}@${record.version} defines a "${record.script}" script: ${truncate(record.command, 400)}`,
        data: { script: record.script, command: truncate(record.command, 2000) },
      },
      {
        kind: 'not-executed',
        message: 'Deplyze inspected this script as text only and did not execute it.',
      },
      {
        kind: 'reachability',
        message: record.direct ? 'This is a direct dependency.' : 'This package is pulled in transitively.',
        data: { direct: record.direct },
      },
    ];
    for (const pattern of record.suspicious) {
      evidence.push({ kind: 'suspicious-pattern', message: `Script ${pattern}.` });
    }
    for (const path of paths) {
      evidence.push({
        kind: 'dependency-path',
        message: `Path: ${path.formatted}`,
        data: { path: path.ids },
      });
    }

    findings.push(
      createFinding({
        category: 'supply-chain',
        severity,
        confidence: hasSuspicious ? 'medium' : 'high',
        title: hasSuspicious
          ? `${label} in ${record.package}@${record.version} (${record.script})`
          : `Lifecycle script in ${record.package}@${record.version} (${record.script})`,
        description:
          `${record.package}@${record.version} runs a "${record.script}" script when installed. ` +
          (hasSuspicious
            ? `The script matches patterns that warrant review: ${record.suspicious.join('; ')}. ` +
              'This is a heuristic signal, not evidence of malicious intent — legitimate packages also use these techniques.'
            : 'Install-time scripts execute with your privileges and are a common supply-chain attack vector. Review the command before trusting the package.'),
        package: record.package,
        version: record.version,
        ecosystem: 'npm',
        source: 'supply-chain/lifecycle-scripts',
        stableId: `lifecycle|${record.package}|${record.version}|${record.script}`,
        evidence,
        remediation: {
          summary: hasSuspicious
            ? `Read the "${record.script}" script in ${record.package}'s package.json and confirm you trust the publisher.`
            : `Confirm the "${record.script}" script is expected for this package.`,
          steps: [
            `Inspect the script source: npm view ${record.package}@${record.version} scripts.${record.script}`,
            'Consider disabling lifecycle scripts for installs you do not trust (`npm install --ignore-scripts`).',
            record.direct
              ? 'If the script is unexpected, replace the dependency with a trusted alternative.'
              : 'Identify the direct dependency that introduces this package and check whether a newer release removes the script.',
          ],
        },
        references: [`https://www.npmjs.com/package/${record.package}?activeTab=code`],
      }),
    );
  }
  return findings;
}

function truncate(value: string, max: number): string {
  return value.length <= max ? value : `${value.slice(0, max)}…`;
}

export const lifecycleScanner: Scanner = {
  id: 'supply-chain/lifecycle-scripts',
  description: 'Reports install lifecycle scripts from registry metadata without executing them.',
  async run(context: ScanContext): Promise<Finding[]> {
    const records = collectLifecycleScripts(context, context.registryMetadata);
    return lifecycleFindings(records, context);
  },
};
