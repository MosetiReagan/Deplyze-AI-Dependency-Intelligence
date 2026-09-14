import { createFinding, type DependencyNode, type Finding } from '@deplyze/core';
import type { RegistryMetadata } from './registry.js';
import { splitPackageName } from './levenshtein.js';
import type { ScanContext, Scanner } from './types.js';

/**
 * Dependencies that are almost never imported directly and are therefore
 * excluded from "unused" reporting by default.
 */
export const DEFAULT_UNUSED_IGNORES: readonly string[] = [
  '@types/*',
  'typescript',
  'tslib',
  'ts-node',
  'prettier',
  'eslint',
  'eslint-*',
  '@eslint/*',
  '@typescript-eslint/*',
  'husky',
  'lint-staged',
  'nodemon',
  'rimraf',
  'cross-env',
  'dotenv-cli',
  'npm-run-all',
  'concurrently',
  'patch-package',
  'npm-check-updates',
  'serve',
  'http-server',
];

export type UnusedConfidence = 'high' | 'medium' | 'low';

export interface UnusedResult {
  node: DependencyNode;
  reason: string;
  confidence: UnusedConfidence;
  /** True when Deplyze cannot rule out dynamic usage. */
  possiblyDynamic: boolean;
}

function matchesIgnore(name: string, patterns: string[]): boolean {
  for (const pattern of patterns) {
    if (pattern.endsWith('/*')) {
      if (name.startsWith(pattern.slice(0, -1))) return true;
      continue;
    }
    if (pattern.endsWith('*')) {
      if (name.startsWith(pattern.slice(0, -1))) return true;
      continue;
    }
    if (pattern === name) return true;
  }
  return false;
}

/** Command names a package exposes, so script usage can be attributed. */
export function binNamesFor(name: string, metadata: RegistryMetadata | undefined, version: string): string[] {
  const entry = metadata?.versions.find((candidate) => candidate.version === version);
  if (!entry?.bin) return [];
  // The bin map is `commandName -> scriptPath`; the command name is the key.
  return Object.keys(entry.bin);
}

export function findUnusedDependencies(context: ScanContext): UnusedResult[] {
  const usage = context.sourceUsage;
  if (!usage) return [];
  const ignores = [
    ...DEFAULT_UNUSED_IGNORES,
    ...context.config.unused.ignore,
    ...context.config.packages.unusedAllow,
  ];
  const results: UnusedResult[] = [];

  const scriptTokens = new Set<string>();
  for (const token of usage.scriptCommands) {
    scriptTokens.add(token.toLowerCase());
    // `eslint-plugin-x` is often invoked as `eslint`; capture the base too.
    scriptTokens.add(token.replace(/^@[^/]+\//, '').toLowerCase());
  }
  const configRefs = new Set<string>();
  for (const ref of usage.configReferences) {
    configRefs.add(ref.toLowerCase());
    configRefs.add(ref.replace(/^@[^/]+\//, '').toLowerCase());
  }

  for (const node of context.graph.allNodes()) {
    if (!node.direct || node.depth !== 1) continue;
    if (!node.workspace) continue;
    if (matchesIgnore(node.name, ignores)) continue;
    if (context.config.packages.allowed.includes(node.name)) continue;

    const { base } = splitPackageName(node.name);
    const candidates = new Set<string>([node.name, base, node.name.toLowerCase(), base.toLowerCase()]);
    if (usage.imported.has(node.name) || usage.imported.has(base)) continue;

    const bins = binNamesFor(node.name, context.registryMetadata.get(node.name), node.version);
    const binMatched = bins.some(
      (bin) =>
        scriptTokens.has(bin.toLowerCase()) || scriptTokens.has(bin.toLowerCase().replace(/^@[^/]+\//, '')),
    );
    if (binMatched) continue;

    const referenced = [...candidates].some((candidate) => configRefs.has(candidate));
    if (referenced) continue;

    const possiblyDynamic = usage.hasDynamicImports;
    const truncated = usage.truncated || usage.skippedFiles > 0;
    const confidence: UnusedConfidence = possiblyDynamic || truncated ? 'low' : 'high';

    results.push({
      node,
      reason: possiblyDynamic
        ? 'No static import, require, script or config reference was found, but the project contains dynamic imports that Deplyze cannot resolve.'
        : truncated
          ? 'No reference was found, but Deplyze could not read every project file, so this may be a false positive.'
          : 'No import, require, script invocation or configuration reference was found anywhere in the scanned sources.',
      confidence,
      possiblyDynamic,
    });
  }
  return results;
}

export const unusedScanner: Scanner = {
  id: 'unused/dependencies',
  description: 'Detects likely-unused direct dependencies using static usage evidence.',
  async run(context: ScanContext): Promise<Finding[]> {
    if (!context.config.unused.enabled) return [];
    const results = findUnusedDependencies(context);
    return results.map((result) => {
      const { node } = result;
      const label =
        result.confidence === 'high'
          ? 'Likely unused dependency'
          : result.possiblyDynamic
            ? 'Possibly unused dependency (dynamic usage detected)'
            : 'Unable to determine usage with confidence';
      return createFinding({
        category: 'unused',
        severity: node.dev ? 'info' : 'low',
        confidence: result.confidence,
        title: `${label}: ${node.name}@${node.version}`,
        description:
          `${node.name} is declared as a ${node.dev ? 'development ' : ''}dependency in ${
            node.workspace === '.' ? 'package.json' : `${node.workspace}/package.json`
          }, but Deplyze found no static reference to it. ` +
          result.reason +
          ' Deplyze never removes dependencies automatically — treat this as a prompt to review.',
        package: node.name,
        version: node.version,
        ecosystem: node.ecosystem,
        source: 'unused/dependencies',
        stableId: `unused|${node.name}|${node.workspace ?? ''}`,
        evidence: [
          {
            kind: 'declaration',
            message: `Declared in ${node.workspace === '.' ? 'package.json' : `${node.workspace}/package.json`} as "${node.declaredRange ?? node.version}".`,
            data: { workspace: node.workspace, range: node.declaredRange },
          },
          { kind: 'search', message: result.reason },
          {
            kind: 'scan-scope',
            message:
              `${context.sourceUsage?.filesScanned ?? 0} source/config files were scanned` +
              (context.sourceUsage?.hasDynamicImports ? ' and dynamic imports were detected.' : '.'),
            data: {
              filesScanned: context.sourceUsage?.filesScanned,
              truncated: context.sourceUsage?.truncated,
              skippedFiles: context.sourceUsage?.skippedFiles,
            },
          },
        ],
        remediation: {
          summary:
            result.confidence === 'high'
              ? `Remove ${node.name} from the manifest if it is genuinely unused.`
              : `Confirm whether ${node.name} is used before removing it.`,
          steps: [
            `Search the repository for "${node.name}" (including config files and CI scripts).`,
            'Some packages are used only at runtime by tooling (for example, a plugin loaded by name).',
            `If it is unused: npm uninstall ${node.name}`,
          ],
        },
      });
    });
  },
};
