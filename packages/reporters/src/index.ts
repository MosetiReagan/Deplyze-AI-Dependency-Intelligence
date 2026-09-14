export * from './types.js';
export * from './color.js';
export * from './serialize.js';
export * from './locate.js';
export { terminalReporter, renderTerminal } from './terminal.js';
export { jsonReporter } from './json.js';
export { markdownReporter, renderMarkdown } from './markdown.js';
export { sarifReporter, renderSarif } from './sarif.js';
export { htmlReporter, renderHtml } from './html.js';

import type { Reporter } from './types.js';
import { terminalReporter } from './terminal.js';
import { jsonReporter } from './json.js';
import { markdownReporter } from './markdown.js';
import { sarifReporter } from './sarif.js';
import { htmlReporter } from './html.js';
import { DeplyzeError, ErrorCode } from '@deplyze/core';

export const REPORTERS: readonly Reporter[] = [
  terminalReporter,
  jsonReporter,
  markdownReporter,
  sarifReporter,
  htmlReporter,
];

export function getReporter(format: string): Reporter {
  const reporter = REPORTERS.find((candidate) => candidate.id === format);
  if (!reporter) {
    throw new DeplyzeError(ErrorCode.DEPLYZE_E_USAGE, `Unknown report format: ${format}`, {
      hint: `Supported formats: ${REPORTERS.map((candidate) => candidate.id).join(', ')}.`,
    });
  }
  return reporter;
}
