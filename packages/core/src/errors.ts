/** Stable error codes surfaced by the CLI and API. Never change an existing code. */
export const ErrorCode = {
  DEPLYZE_OK: 'DEPLYZE_OK',
  // Configuration / usage (exit 2)
  DEPLYZE_E_CONFIG: 'DEPLYZE_E_CONFIG',
  DEPLYZE_E_USAGE: 'DEPLYZE_E_USAGE',
  DEPLYZE_E_PROJECT_NOT_FOUND: 'DEPLYZE_E_PROJECT_NOT_FOUND',
  DEPLYZE_E_NO_MANIFEST: 'DEPLYZE_E_NO_MANIFEST',
  DEPLYZE_E_UNSUPPORTED_ECOSYSTEM: 'DEPLYZE_E_UNSUPPORTED_ECOSYSTEM',
  // Parsing (exit 2)
  DEPLYZE_E_MANIFEST_PARSE: 'DEPLYZE_E_MANIFEST_PARSE',
  DEPLYZE_E_LOCKFILE_PARSE: 'DEPLYZE_E_LOCKFILE_PARSE',
  DEPLYZE_E_LOCKFILE_UNSUPPORTED: 'DEPLYZE_E_LOCKFILE_UNSUPPORTED',
  DEPLYZE_E_OVERSIZED_FILE: 'DEPLYZE_E_OVERSIZED_FILE',
  // Network (exit 2)
  DEPLYZE_E_NETWORK: 'DEPLYZE_E_NETWORK',
  DEPLYZE_E_REGISTRY: 'DEPLYZE_E_REGISTRY',
  DEPLYZE_E_ADVISORY: 'DEPLYZE_E_ADVISORY',
  DEPLYZE_E_OFFLINE_NO_CACHE: 'DEPLYZE_E_OFFLINE_NO_CACHE',
  // AI (exit 2)
  DEPLYZE_E_AI_DISABLED: 'DEPLYZE_E_AI_DISABLED',
  DEPLYZE_E_AI_PROVIDER: 'DEPLYZE_E_AI_PROVIDER',
  DEPLYZE_E_AI_REDACTION: 'DEPLYZE_E_AI_REDACTION',
  // Policy (exit 1)
  DEPLYZE_E_POLICY_VIOLATION: 'DEPLYZE_E_POLICY_VIOLATION',
  // Internal (exit 2)
  DEPLYZE_E_INTERNAL: 'DEPLYZE_E_INTERNAL',
} as const;

export type ErrorCodeValue = (typeof ErrorCode)[keyof typeof ErrorCode];

/** Exit codes are part of Deplyze's public contract. */
export const EXIT = {
  PASS: 0,
  POLICY_VIOLATION: 1,
  ERROR: 2,
} as const;

const EXIT_BY_CODE: Record<string, number> = {
  [ErrorCode.DEPLYZE_E_POLICY_VIOLATION]: EXIT.POLICY_VIOLATION,
};

export class DeplyzeError extends Error {
  readonly code: ErrorCodeValue;
  readonly hint?: string;
  readonly details?: Record<string, unknown>;
  override readonly cause?: unknown;

  constructor(
    code: ErrorCodeValue,
    message: string,
    options: { hint?: string; details?: Record<string, unknown>; cause?: unknown } = {},
  ) {
    super(message);
    this.name = 'DeplyzeError';
    this.code = code;
    this.hint = options.hint;
    this.details = options.details;
    this.cause = options.cause;
  }

  get exitCode(): number {
    return EXIT_BY_CODE[this.code] ?? EXIT.ERROR;
  }
}

export function isDeplyzeError(value: unknown): value is DeplyzeError {
  return value instanceof DeplyzeError;
}

/** Human-readable diagnostic block used by the CLI's default error handler. */
export function formatError(error: unknown): string {
  if (isDeplyzeError(error)) {
    const lines = [`${error.message}`, '', `Code: ${error.code}`];
    if (error.hint) lines.push(`Try: ${error.hint}`);
    return lines.join('\n');
  }
  if (error instanceof Error) {
    return `${error.message}\n\nCode: ${ErrorCode.DEPLYZE_E_INTERNAL}`;
  }
  return `An unknown error occurred.\n\nCode: ${ErrorCode.DEPLYZE_E_INTERNAL}`;
}
