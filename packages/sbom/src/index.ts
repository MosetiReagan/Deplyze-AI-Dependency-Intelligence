import type { ScanResult } from '@deplyze/scanners';
import { buildCycloneDx, type SbomOptions } from './cyclonedx.js';
import { buildSpdx, type SpdxOptions } from './spdx.js';

export * from './purl.js';
export * from './cyclonedx.js';
export * from './spdx.js';

export type SbomFormat = 'cyclonedx' | 'spdx';

export interface SbomGenerateOptions extends SbomOptions, SpdxOptions {
  format?: SbomFormat;
  pretty?: boolean;
}

export function generateSbom(result: ScanResult, options: SbomGenerateOptions = {}): string {
  const format = options.format ?? 'cyclonedx';
  const payload = format === 'spdx' ? buildSpdx(result, options) : buildCycloneDx(result, options);
  return `${JSON.stringify(payload, null, options.pretty === false ? 0 : 2)}\n`;
}

export function sbomContentType(format: SbomFormat): string {
  return format === 'spdx' ? 'application/spdx+json' : 'application/vnd.cyclonedx+json';
}

export function sbomExtension(format: SbomFormat): string {
  return format === 'spdx' ? 'spdx.json' : 'cdx.json';
}
