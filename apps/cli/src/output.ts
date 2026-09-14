import { mkdir, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { DeplyzeError, ErrorCode } from '@deplyze/core';
import type { ScanResult } from '@deplyze/scanners';
import { getReporter, type ReportOptions } from '@deplyze/reporters';

export interface EmitOptions extends ReportOptions {
  /** Format id: terminal | json | markdown | sarif | html. */
  format: string;
  /** Write to this file instead of stdout. */
  file?: string;
  /** Only write to the file; suppress stdout. */
  quiet?: boolean;
}

/**
 * Render a scan result and deliver it to stdout or a file.
 *
 * Writing to a file never implicitly touches the network or the project, and a
 * missing parent directory is created only inside the project root.
 */
export async function emit(result: ScanResult, options: EmitOptions): Promise<string> {
  const reporter = getReporter(options.format);
  const payload = await reporter.render(result, options);
  if (options.file) {
    const absolute = path.resolve(result.project.root, options.file);
    await mkdir(path.dirname(absolute), { recursive: true });
    await writeFile(absolute, payload, 'utf8');
    if (!options.quiet) {
      process.stdout.write(
        `Wrote ${options.format} report to ${path.relative(result.project.root, absolute)}\n`,
      );
    }
  } else if (!options.quiet) {
    process.stdout.write(payload.endsWith('\n') ? payload : `${payload}\n`);
  }
  return payload;
}

export function resolveFormat(flags: { format?: string; json?: boolean; sarif?: boolean }): string {
  if (flags.format) return flags.format;
  if (flags.json) return 'json';
  if (flags.sarif) return 'sarif';
  return 'terminal';
}

export function assertWritablePath(root: string, file: string): void {
  const absolute = path.resolve(root, file);
  const relative = path.relative(path.resolve(root), absolute);
  if (relative.startsWith('..') || path.isAbsolute(relative)) {
    throw new DeplyzeError(ErrorCode.DEPLYZE_E_USAGE, `Refusing to write outside the project root: ${file}`, {
      hint: 'Report paths must be relative to the project root.',
    });
  }
}

/** Standard `deplyze explain`-style plain text output. */
export function printHeading(title: string): void {
  process.stdout.write(`${title}\n${'─'.repeat(Math.min(title.length, 72))}\n`);
}
