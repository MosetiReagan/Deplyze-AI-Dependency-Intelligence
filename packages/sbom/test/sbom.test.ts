import { describe, expect, it } from 'vitest';
import {
  buildCycloneDx,
  buildSpdx,
  generateSbom,
  purlFor,
  sbomContentType,
  sbomExtension,
  sriToHex,
} from '../src/index.js';
import { makeFinding, makeNode, makeResult } from '../../../test/helpers.js';

const result = makeResult({
  nodes: [
    {
      id: 'root:.',
      name: 'app',
      version: '1.0.0',
      ecosystem: 'npm',
      direct: false,
      dev: false,
      optional: false,
      peer: false,
      depth: 0,
      dependencies: [],
    },
    makeNode({
      name: 'lodash',
      version: '4.17.20',
      direct: true,
      license: 'MIT',
      integrity: 'sha512-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=',
      resolved: 'https://registry.npmjs.org/lodash/-/lodash-4.17.20.tgz',
    }),
    makeNode({ name: '@scope/thing', version: '1.2.0', depth: 2, license: 'Apache-2.0' }),
  ],
  edges: [
    ['root:.', 'npm:lodash@4.17.20'],
    ['npm:lodash@4.17.20', 'npm:@scope/thing@1.2.0'],
  ],
  findings: [
    makeFinding({
      package: 'lodash',
      version: '4.17.20',
      advisoryId: 'GHSA-test-1111-2222',
      severity: 'high',
      title: 'Vulnerability',
    }),
  ],
});

describe('purlFor', () => {
  it('builds ecosystem purls, including scoped npm names', () => {
    expect(purlFor({ ecosystem: 'npm', name: 'lodash', version: '4.17.21' })).toBe('pkg:npm/lodash@4.17.21');
    expect(purlFor({ ecosystem: 'npm', name: '@scope/thing', version: '1.0.0' })).toBe(
      'pkg:npm/@scope/thing@1.0.0',
    );
  });
});

describe('sriToHex', () => {
  it('converts an SRI hash into hex', () => {
    const converted = sriToHex('sha512-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=');
    expect(converted?.algorithm).toBe('SHA-512');
    expect(converted?.hex).toMatch(/^0+$/);
  });

  it('returns undefined for malformed integrity values', () => {
    expect(sriToHex('not-a-hash')).toBeUndefined();
  });
});

describe('buildCycloneDx', () => {
  it('lists every non-root package as a component with licenses and hashes', () => {
    const bom = buildCycloneDx(result) as Record<string, unknown>;
    expect(bom.bomFormat).toBe('CycloneDX');
    expect(bom.specVersion).toBe('1.5');
    const components = bom.components as Array<Record<string, unknown>>;
    expect(components).toHaveLength(2);
    const lodash = components.find((component) => component.name === 'lodash')!;
    expect(lodash.purl).toBe('pkg:npm/lodash@4.17.20');
    expect(lodash.licenses).toEqual([{ license: { id: 'MIT' } }]);
    expect(lodash.hashes).toBeDefined();
  });

  it('emits dependency relationships and vulnerability records', () => {
    const bom = buildCycloneDx(result) as Record<string, unknown>;
    expect((bom.dependencies as unknown[]).length).toBeGreaterThan(0);
    const vulnerabilities = bom.vulnerabilities as Array<Record<string, unknown>>;
    expect(vulnerabilities[0]?.id).toBe('GHSA-test-1111-2222');
  });

  it('supports a deterministic serial number', () => {
    const bom = buildCycloneDx(result, { serialNumber: 'urn:uuid:fixed' }) as Record<string, unknown>;
    expect(bom.serialNumber).toBe('urn:uuid:fixed');
  });
});

describe('buildSpdx', () => {
  it('produces a valid SPDX 2.3 document with purl external refs', () => {
    const doc = buildSpdx(result) as Record<string, unknown>;
    expect(doc.spdxVersion).toBe('SPDX-2.3');
    const packages = doc.packages as Array<Record<string, unknown>>;
    const lodash = packages.find((entry) => entry.name === 'lodash')!;
    expect(lodash.licenseConcluded).toBe('MIT');
    expect(lodash.externalRefs).toBeDefined();
    const relationships = doc.relationships as Array<Record<string, unknown>>;
    expect(relationships.some((relationship) => relationship.relationshipType === 'DESCRIBES')).toBe(true);
  });

  it('reports NOASSERTION for an unknown license rather than guessing', () => {
    const doc = buildSpdx(makeResult()) as Record<string, unknown>;
    const packages = doc.packages as Array<Record<string, unknown>>;
    const minimist = packages.find((entry) => entry.name === 'minimist');
    // The default fixture node has an MIT license; the root always asserts nothing.
    const root = packages.find((entry) => entry.name === 'fixture-app')!;
    expect(root.licenseConcluded).toBe('NOASSERTION');
    expect(minimist).toBeDefined();
  });
});

describe('generateSbom', () => {
  it('emits parseable JSON for both formats and reports content types', () => {
    const cyclonedx = JSON.parse(generateSbom(result, { format: 'cyclonedx' }));
    const spdx = JSON.parse(generateSbom(result, { format: 'spdx' }));
    expect(cyclonedx.bomFormat).toBe('CycloneDX');
    expect(spdx.spdxVersion).toBe('SPDX-2.3');
    expect(sbomContentType('cyclonedx')).toBe('application/vnd.cyclonedx+json');
    expect(sbomContentType('spdx')).toBe('application/spdx+json');
    expect(sbomExtension('cyclonedx')).toBe('cdx.json');
    expect(sbomExtension('spdx')).toBe('spdx.json');
  });
});
