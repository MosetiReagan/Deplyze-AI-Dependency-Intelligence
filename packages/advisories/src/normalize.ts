import { z } from 'zod';
import type { Advisory, Ecosystem, Severity } from '@deplyze/core';
import { severityFromCvss, scoreCvssVector } from './cvss.js';

const osvReferenceSchema = z.object({ type: z.string().optional(), url: z.string() });

const osvEventSchema = z.object({
  introduced: z.string().optional(),
  fixed: z.string().optional(),
  last_affected: z.string().optional(),
  limit: z.string().optional(),
});

const osvRangeSchema = z.object({
  type: z.string(),
  repo: z.string().optional(),
  events: z.array(osvEventSchema),
});

const osvAffectedSchema = z.object({
  package: z.object({ ecosystem: z.string(), name: z.string(), purl: z.string().optional() }),
  ranges: z.array(osvRangeSchema).optional(),
  versions: z.array(z.string()).optional(),
  ecosystem_specific: z.record(z.string(), z.unknown()).optional(),
  database_specific: z.record(z.string(), z.unknown()).optional(),
});

export const osvVulnerabilitySchema = z.object({
  id: z.string(),
  aliases: z.array(z.string()).optional(),
  summary: z.string().optional(),
  details: z.string().optional(),
  modified: z.string().optional(),
  published: z.string().optional(),
  withdrawn: z.string().optional(),
  references: z.array(osvReferenceSchema).optional(),
  affected: z.array(osvAffectedSchema).optional(),
  severity: z.array(z.object({ type: z.string(), score: z.string() })).optional(),
  database_specific: z.record(z.string(), z.unknown()).optional(),
});

export type OsvVulnerability = z.infer<typeof osvVulnerabilitySchema>;

const ECOSYSTEM_MAP: Record<string, Ecosystem> = {
  npm: 'npm',
  PyPI: 'pypi',
  'crates.io': 'cargo',
  Go: 'go',
  Maven: 'maven',
  NuGet: 'nuget',
  Packagist: 'composer',
  RubyGems: 'gem',
};

export function mapEcosystem(value: string): Ecosystem | undefined {
  return ECOSYSTEM_MAP[value];
}

const SEVERITY_WORDS: Record<string, Severity> = {
  critical: 'critical',
  high: 'high',
  moderate: 'medium',
  medium: 'medium',
  low: 'low',
  informational: 'info',
  info: 'info',
  none: 'info',
  unknown: 'unknown',
};

function severityFromDatabaseSpecific(value: unknown): Severity | undefined {
  if (typeof value !== 'string') return undefined;
  return SEVERITY_WORDS[value.toLowerCase()];
}

/**
 * Convert OSV `events` into a semver range expression.
 *
 * OSV expresses a range as an ordered event stream. Deplyze converts each
 * `introduced`..`fixed`/`last_affected` pair into a conventional range so the
 * same matcher that handles npm ranges can handle advisories.
 */
export function eventsToRange(
  events: Array<{ introduced?: string; fixed?: string; last_affected?: string; limit?: string }>,
): string | undefined {
  const clauses: string[] = [];
  let introduced: string | undefined;
  for (const event of events) {
    if (event.introduced !== undefined) {
      introduced = event.introduced;
      continue;
    }
    if (event.fixed !== undefined || event.last_affected !== undefined) {
      const lower = introduced === undefined || introduced === '0' ? undefined : `>=${introduced}`;
      const upper = event.fixed !== undefined ? `<${event.fixed}` : `<=${event.last_affected as string}`;
      clauses.push([lower, upper].filter(Boolean).join(' '));
      introduced = undefined;
      continue;
    }
    if (event.limit !== undefined && introduced !== undefined) {
      clauses.push(`>=${introduced} <${event.limit}`);
      introduced = undefined;
    }
  }
  if (introduced !== undefined) {
    clauses.push(introduced === '0' ? '*' : `>=${introduced}`);
  }
  const filtered = clauses.filter((clause) => clause.length > 0);
  return filtered.length > 0 ? filtered.join(' || ') : undefined;
}

function parseDate(value: string | undefined): string | undefined {
  if (!value) return undefined;
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? undefined : value;
}

export interface NormalizeOptions {
  source: string;
  fromCache?: boolean;
}

/**
 * Normalize an OSV record into zero or more Deplyze advisories — one per
 * affected package, because Deplyze never conflates packages that share an
 * advisory id.
 */
export function normalizeOsv(vuln: OsvVulnerability, options: NormalizeOptions): Advisory[] {
  if (vuln.withdrawn) return [];
  const advisories: Advisory[] = [];

  for (const affected of vuln.affected ?? []) {
    const ecosystem = mapEcosystem(affected.package.ecosystem);
    if (!ecosystem) continue;
    const name = affected.package.name;
    if (!name) continue;

    const ranges = new Set<string>();
    const fixedVersions = new Set<string>();
    for (const range of affected.ranges ?? []) {
      if (!range.type.toUpperCase().includes('SEMVER') && !range.type.toUpperCase().includes('ECOSYSTEM')) {
        continue;
      }
      const expression = eventsToRange(range.events);
      if (expression) ranges.add(expression);
      for (const event of range.events) {
        if (event.fixed) fixedVersions.add(event.fixed);
      }
    }

    const dbSeverity = severityFromDatabaseSpecific(affected.database_specific?.severity);
    let cvss: number | undefined;
    let cvssVector: string | undefined;
    for (const entry of vuln.severity ?? []) {
      if (!entry.score.startsWith('CVSS:')) continue;
      const scored = scoreCvssVector(entry.score);
      if (scored) {
        cvss = Math.max(cvss ?? 0, scored.score);
        cvssVector = entry.score;
      } else if (!cvssVector) {
        cvssVector = entry.score;
      }
    }
    let severity: Severity | undefined =
      dbSeverity ?? severityFromDatabaseSpecific(vuln.database_specific?.severity);
    if (!severity && cvss !== undefined) severity = severityFromCvss(cvss);

    const advisory: Advisory = {
      id: vuln.id,
      aliases: (vuln.aliases ?? []).filter(Boolean),
      package: name,
      ecosystem,
      affectedRanges: [...ranges],
      affectedVersions: affected.versions ?? [],
      fixedVersions: [...fixedVersions],
      summary: vuln.summary?.trim() || `Advisory ${vuln.id}`,
      references: (vuln.references ?? []).map((ref) => ref.url).filter(Boolean),
      source: options.source,
    };
    if (severity) advisory.severity = severity;
    if (cvss !== undefined) advisory.cvss = cvss;
    if (cvssVector) advisory.cvssVector = cvssVector;
    if (vuln.details) advisory.details = vuln.details;
    const published = parseDate(vuln.published);
    if (published) advisory.publishedAt = published;
    const modified = parseDate(vuln.modified);
    if (modified) advisory.modifiedAt = modified;
    if (options.fromCache) advisory.fromCache = true;
    advisories.push(advisory);
  }

  return advisories;
}
