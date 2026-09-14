import type { ScanResult } from '@deplyze/scanners';
import type { ColorMode } from './color.js';

export interface ReportOptions {
  color?: ColorMode;
  /** Include informational findings in the output. */
  includeInfo?: boolean;
  /** Limit the number of findings rendered in the terminal summary. */
  maxFindings?: number;
  /** Absolute path used to build relative SARIF artifact URIs. */
  root?: string;
  /** Pretty-print JSON output. */
  pretty?: boolean;
  /** Report generation timestamp override (deterministic tests). */
  generatedAt?: string;
}

export interface Reporter {
  id: 'terminal' | 'json' | 'markdown' | 'sarif' | 'html';
  contentType: string;
  extension: string;
  render(result: ScanResult, options?: ReportOptions): Promise<string> | string;
}
