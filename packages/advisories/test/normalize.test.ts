import { describe, expect, it } from 'vitest';
import { eventsToRange, mapEcosystem, normalizeOsv, type OsvVulnerability } from '../src/index.js';

describe('mapEcosystem', () => {
  it('maps OSV ecosystem names onto Deplyze ecosystems', () => {
    expect(mapEcosystem('npm')).toBe('npm');
    expect(mapEcosystem('PyPI')).toBe('pypi');
    expect(mapEcosystem('crates.io')).toBe('cargo');
    expect(mapEcosystem('unknown-eco')).toBeUndefined();
  });
});

describe('eventsToRange', () => {
  it('converts introduced/fixed pairs into a semver range', () => {
    expect(eventsToRange([{ introduced: '1.0.0' }, { fixed: '1.2.0' }])).toBe('>=1.0.0 <1.2.0');
  });

  it('treats introduced 0 as "from the beginning"', () => {
    expect(eventsToRange([{ introduced: '0' }, { fixed: '2.0.0' }])).toBe('<2.0.0');
  });

  it('supports last_affected and limit', () => {
    expect(eventsToRange([{ introduced: '1.0.0' }, { last_affected: '1.5.0' }])).toBe('>=1.0.0 <=1.5.0');
    expect(eventsToRange([{ introduced: '1.0.0' }, { limit: '2.0.0' }])).toBe('>=1.0.0 <2.0.0');
  });

  it('joins disjoint ranges with a union', () => {
    const events = [{ introduced: '1.0.0' }, { fixed: '1.2.0' }, { introduced: '2.0.0' }, { fixed: '2.1.0' }];
    expect(eventsToRange(events)).toBe('>=1.0.0 <1.2.0 || >=2.0.0 <2.1.0');
  });

  it('returns undefined when there is nothing usable', () => {
    expect(eventsToRange([])).toBeUndefined();
  });
});

const baseVuln: OsvVulnerability = {
  id: 'GHSA-aaaa-bbbb-cccc',
  aliases: ['CVE-2024-0001'],
  summary: 'Prototype pollution in example-package',
  published: '2024-01-01T00:00:00Z',
  modified: '2024-02-01T00:00:00Z',
  references: [{ type: 'WEB', url: 'https://example.com/advisory' }],
  severity: [{ type: 'CVSS_V3', score: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' }],
  affected: [
    {
      package: { ecosystem: 'npm', name: 'example-package' },
      ranges: [{ type: 'SEMVER', events: [{ introduced: '0.0.0' }, { fixed: '2.0.0' }] }],
      versions: ['1.0.0', '1.5.0'],
    },
  ],
};

describe('normalizeOsv', () => {
  it('normalizes an advisory into the common model', () => {
    const advisories = normalizeOsv(baseVuln, { source: 'osv' });
    expect(advisories).toHaveLength(1);
    const advisory = advisories[0]!;
    expect(advisory.id).toBe('GHSA-aaaa-bbbb-cccc');
    expect(advisory.aliases).toEqual(['CVE-2024-0001']);
    expect(advisory.package).toBe('example-package');
    expect(advisory.ecosystem).toBe('npm');
    expect(advisory.affectedVersions).toEqual(['1.0.0', '1.5.0']);
    expect(advisory.fixedVersions).toEqual(['2.0.0']);
    expect(advisory.affectedRanges).toEqual(['>=0.0.0 <2.0.0']);
    expect(advisory.cvss).toBe(9.8);
    expect(advisory.severity).toBe('critical');
    expect(advisory.references).toEqual(['https://example.com/advisory']);
  });

  it('drops withdrawn advisories entirely', () => {
    expect(normalizeOsv({ ...baseVuln, withdrawn: '2024-03-01T00:00:00Z' }, { source: 'osv' })).toEqual([]);
  });

  it('skips unsupported ecosystems instead of guessing', () => {
    const vuln: OsvVulnerability = {
      ...baseVuln,
      affected: [{ package: { ecosystem: 'Unknown-Ecosystem', name: 'x' }, ranges: [] }],
    };
    expect(normalizeOsv(vuln, { source: 'osv' })).toEqual([]);
  });

  it('prefers an explicit database severity over a derived one', () => {
    const vuln: OsvVulnerability = {
      ...baseVuln,
      affected: [
        {
          ...baseVuln.affected![0]!,
          database_specific: { severity: 'MODERATE' },
        },
      ],
    };
    expect(normalizeOsv(vuln, { source: 'osv' })[0]?.severity).toBe('medium');
  });

  it('marks advisories that came from the cache', () => {
    const advisory = normalizeOsv(baseVuln, { source: 'offline-cache', fromCache: true })[0]!;
    expect(advisory.source).toBe('offline-cache');
    expect(advisory.fromCache).toBe(true);
  });
});
