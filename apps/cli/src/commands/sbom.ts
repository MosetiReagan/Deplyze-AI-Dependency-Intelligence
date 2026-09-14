import { generateSbom, type SbomFormat } from '@deplyze/sbom';
import { packageCount } from '@deplyze/scanners';
import { runScanCommand, type ScanFlags } from './shared.js';
import { assertWritablePath } from '../output.js';
import { mkdir, writeFile } from 'node:fs/promises';
import path from 'node:path';

export interface SbomFlags extends ScanFlags {
  format?: string;
  output?: string;
}

export async function sbomCommand(flags: SbomFlags): Promise<number> {
  const { context, result } = await runScanCommand(flags);
  const format = (flags.format ?? 'cyclonedx') as SbomFormat;
  if (format !== 'cyclonedx' && format !== 'spdx') {
    process.stderr.write(`Unsupported SBOM format: ${format}. Use "cyclonedx" or "spdx".\n`);
    return 2;
  }

  const payload = generateSbom(result, { format, pretty: true });
  if (flags.json) {
    process.stdout.write(payload);
    return 0;
  }
  const extension = format === 'spdx' ? 'spdx.json' : 'cdx.json';
  const file = flags.output ?? `deplyze-sbom.${extension}`;
  assertWritablePath(result.project.root, file);
  const absolute = path.resolve(result.project.root, file);
  await mkdir(path.dirname(absolute), { recursive: true });
  await writeFile(absolute, payload, 'utf8');
  process.stdout.write(
    `Wrote ${format} SBOM with ${packageCount(result)} components to ${path.relative(result.project.root, absolute)}\n`,
  );
  void context;
  return 0;
}
