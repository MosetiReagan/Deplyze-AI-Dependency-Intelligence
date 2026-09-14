/**
 * Secret redaction.
 *
 * Applied to any payload that may leave the process boundary (AI providers,
 * structured logs, API responses, reports). Redaction is best-effort and
 * defense-in-depth — callers must still avoid placing secrets where they do
 * not belong.
 */

const PATTERNS: Array<{ name: string; regex: RegExp; replace: string }> = [
  { name: 'openai-key', regex: /\bsk-[A-Za-z0-9_-]{16,}\b/g, replace: 'sk-***REDACTED***' },
  { name: 'anthropic-key', regex: /\bsk-ant-[A-Za-z0-9_-]{16,}\b/g, replace: 'sk-ant-***REDACTED***' },
  { name: 'github-token', regex: /\bgh[pousr]_[A-Za-z0-9]{20,}\b/g, replace: 'gh*_***REDACTED***' },
  { name: 'gitlab-token', regex: /\bglpat-[A-Za-z0-9_-]{16,}\b/g, replace: 'glpat-***REDACTED***' },
  { name: 'aws-access-key', regex: /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/g, replace: 'AKIA***REDACTED***' },
  { name: 'google-api-key', regex: /\bAIza[0-9A-Za-z_-]{35}\b/g, replace: 'AIza***REDACTED***' },
  { name: 'npm-token', regex: /\bnpm_[A-Za-z0-9]{30,}\b/g, replace: 'npm_***REDACTED***' },
  { name: 'slack-token', regex: /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/g, replace: 'xox*-***REDACTED***' },
  {
    name: 'jwt',
    regex: /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}\b/g,
    replace: '***JWT-REDACTED***',
  },
  {
    name: 'private-key',
    regex:
      /-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----/g,
    replace: '-----BEGIN PRIVATE KEY-----***REDACTED***-----END PRIVATE KEY-----',
  },
  {
    name: 'basic-auth-url',
    regex: /\b([a-z][a-z0-9+.-]*:\/\/)[^/@\s:]+:[^/@\s]+@/gi,
    replace: '$1***REDACTED***@',
  },
];

const SENSITIVE_KEY =
  /(pass(word|phrase)?|secret|token|api[-_]?key|apikey|auth|credential|private[-_]?key|session|cookie|bearer)/i;

export function redactSecrets(input: string): string {
  let output = input;
  for (const pattern of PATTERNS) {
    output = output.replace(pattern.regex, pattern.replace);
  }
  return output;
}

const ENV_NAME = /^[A-Z0-9_]+$/;
const ENV_SECRET_NAME =
  /(PASSWORD|PASSWD|SECRET|TOKEN|API_?KEY|PRIVATE_?KEY|CREDENTIAL|AUTH|_PAT\b|SESSION)/i;

/** Redact values of environment variables that look like secrets. */
export function redactEnvValue(name: string, value: string | undefined): string | undefined {
  if (value === undefined) return undefined;
  if (!ENV_NAME.test(name)) return redactSecrets(value);
  if (ENV_SECRET_NAME.test(name)) return '***REDACTED***';
  return redactSecrets(value);
}

/**
 * Recursively redact strings inside a JSON-like structure. Objects with
 * sensitive keys are replaced wholesale with a redaction marker.
 */
export function redactObject<T>(value: T, depth = 0): T {
  if (depth > 12) return '***DEPTH-LIMIT***' as unknown as T;
  if (typeof value === 'string') return redactSecrets(value) as unknown as T;
  if (Array.isArray(value)) return value.map((item) => redactObject(item, depth + 1)) as unknown as T;
  if (value && typeof value === 'object') {
    const output: Record<string, unknown> = {};
    for (const [key, item] of Object.entries(value as Record<string, unknown>)) {
      if (SENSITIVE_KEY.test(key) && typeof item !== 'object') {
        output[key] = '***REDACTED***';
      } else {
        output[key] = redactObject(item, depth + 1);
      }
    }
    return output as unknown as T;
  }
  return value;
}
