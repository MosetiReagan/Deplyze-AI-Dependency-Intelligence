import { categoryLabel, type Finding, type Severity } from '@deplyze/core';
import type { ScanResult } from '@deplyze/scanners';
import { locateDependency, type SourceLocation } from './locate.js';
import type { ReportOptions, Reporter } from './types.js';

const SARIF_VERSION = '2.1.0';
const SCHEMA =
  'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json';

/**
 * GitHub code scanning only understands `error`, `warning` and `note`, so the
 * richer Deplyze severity is preserved in `properties.severity` alongside the
 * SARIF level rather than being flattened irreversibly.
 */
function levelFor(severity: Severity): 'error' | 'warning' | 'note' {
  if (severity === 'critical' || severity === 'high') return 'error';
  if (severity === 'medium') return 'warning';
  return 'note';
}

function securitySeverityFor(severity: Severity): string {
  switch (severity) {
    case 'critical':
      return '9.5';
    case 'high':
      return '8.0';
    case 'medium':
      return '5.5';
    case 'low':
      return '2.5';
    default:
      return '0.0';
  }
}

export function renderSarif(result: ScanResult, options: ReportOptions = {}): string {
  const root = options.root ?? result.project.root;
  const rules = new Map<string, Record<string, unknown>>();
  const locationCache = new Map<string, SourceLocation | undefined>();

  const locate = (packageName: string): SourceLocation | undefined => {
    if (!locationCache.has(packageName)) {
      locationCache.set(packageName, locateDependency(root, result, packageName));
    }
    return locationCache.get(packageName);
  };

  const results = result.findings.map((finding: Finding) => {
    const ruleId = finding.advisoryId ? `${finding.source}/${finding.advisoryId}` : finding.source;
    if (!rules.has(ruleId)) {
      rules.set(ruleId, {
        id: ruleId,
        name: ruleId.replace(/[^A-Za-z0-9]+/g, '_'),
        shortDescription: { text: `${categoryLabel(finding.category)}: ${finding.source}` },
        fullDescription: { text: `Deplyze detector ${finding.source} (${categoryLabel(finding.category)}).` },
        defaultConfiguration: { level: levelFor(finding.severity) },
        helpUri:
          finding.references?.[0] ??
          `https://github.com/deplyze/deplyze/blob/main/docs/rules.md#${finding.source.replace(/[^a-z0-9]+/gi, '-')}`,
        properties: {
          category: finding.category,
          tags: ['security', 'dependencies', finding.category],
        },
      });
    }

    const location = finding.package ? locate(finding.package) : undefined;
    const text = [
      finding.title,
      '',
      finding.description,
      '',
      'Evidence:',
      ...finding.evidence.map((evidence) => `  - ${evidence.message}`),
      ...(finding.remediation ? ['', `Remediation: ${finding.remediation.summary}`] : []),
    ].join('\n');

    const resultEntry: Record<string, unknown> = {
      ruleId,
      ruleIndex: [...rules.keys()].indexOf(ruleId),
      level: levelFor(finding.severity),
      message: { text },
      properties: {
        severity: finding.severity,
        confidence: finding.confidence,
        category: finding.category,
        deplyzeId: finding.id,
        package: finding.package,
        version: finding.version,
        advisoryId: finding.advisoryId,
        securitySeverity: securitySeverityFor(finding.severity),
      },
    };

    if (location) {
      resultEntry.locations = [
        {
          physicalLocation: {
            artifactLocation: { uri: location.file, uriBaseId: 'SRCROOT' },
            region: {
              startLine: location.line,
              startColumn: location.column,
              ...(location.snippet ? { snippet: { text: location.snippet } } : {}),
            },
          },
        },
      ];
    } else if (finding.package) {
      resultEntry.locations = [
        {
          logicalLocations: [{ fullyQualifiedName: `npm:${finding.package}@${finding.version ?? ''}` }],
        },
      ];
    }

    if (finding.remediation?.command) {
      resultEntry.fixes = [
        {
          description: { text: finding.remediation.summary },
          artifactChanges: [
            {
              artifactLocation: { uri: location?.file ?? 'package.json' },
              replacements: [
                {
                  deletedRegion: {
                    startLine: location?.line ?? 1,
                    startColumn: location?.column ?? 1,
                  },
                  insertedContent: {
                    text: `"${finding.package}": "${finding.remediation.upgrades?.[0]?.to ?? ''}"`,
                  },
                },
              ],
            },
          ],
        },
      ];
    }

    return resultEntry;
  });

  const sarif = {
    $schema: SCHEMA,
    version: SARIF_VERSION,
    runs: [
      {
        tool: {
          driver: {
            name: 'Deplyze',
            fullName: 'Deplyze — AI Dependency Intelligence',
            informationUri: 'https://github.com/deplyze/deplyze',
            version: '0.1.0',
            semanticVersion: '0.1.0',
            rules: [...rules.values()],
          },
        },
        originalUriBaseIds: {
          SRCROOT: { uri: `file://${root.replace(/\\/g, '/').replace(/\/?$/, '/')}` },
        },
        invocations: [
          {
            executionSuccessful: result.diagnostics.scannerErrors.length === 0,
            startTimeUtc: result.startedAt,
            endTimeUtc: result.finishedAt,
            toolExecutionNotifications: result.diagnostics.scannerErrors.map((error) => ({
              level: 'warning',
              message: { text: `Scanner ${error.scanner} failed: ${error.message}` },
            })),
          },
        ],
        results,
        properties: {
          riskScore: result.risk.overall,
          riskBand: result.risk.band,
          summary: result.summary,
          graphStats: result.stats,
        },
      },
    ],
  };

  return `${JSON.stringify(sarif, null, 2)}\n`;
}

export const sarifReporter: Reporter = {
  id: 'sarif',
  contentType: 'application/sarif+json',
  extension: 'sarif',
  render: renderSarif,
};
