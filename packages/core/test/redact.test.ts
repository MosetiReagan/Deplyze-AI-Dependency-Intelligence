import { describe, expect, it } from 'vitest';
import { redactEnvValue, redactObject, redactSecrets } from '../src/index.js';

describe('redactSecrets', () => {
  it('redacts provider API keys', () => {
    expect(redactSecrets('key=sk-abcdefghijklmnopqrstuvwxyz012345')).not.toContain(
      'abcdefghijklmnopqrstuvwxyz012345',
    );
    expect(redactSecrets('sk-ant-api03-abcdefghijklmnop')).toContain('REDACTED');
    expect(redactSecrets('ghp_abcdefghijklmnopqrstuvwxyz012345')).toContain('REDACTED');
    expect(redactSecrets('AKIAIOSFODNN7EXAMPLE')).toContain('REDACTED');
  });

  it('redacts credentials embedded in URLs', () => {
    const output = redactSecrets('https://user:hunter2@example.com/path');
    expect(output).not.toContain('hunter2');
    expect(output).toContain('example.com');
  });

  it('redacts private keys', () => {
    const pem = '-----BEGIN RSA PRIVATE KEY-----\nMIIEow\n-----END RSA PRIVATE KEY-----';
    expect(redactSecrets(pem)).not.toContain('MIIEow');
  });

  it('leaves ordinary text untouched', () => {
    expect(redactSecrets('lodash@4.17.21 has a prototype pollution issue')).toBe(
      'lodash@4.17.21 has a prototype pollution issue',
    );
  });
});

describe('redactEnvValue', () => {
  it('redacts secret-looking variable names entirely', () => {
    expect(redactEnvValue('NPM_TOKEN', 'abc123')).toBe('***REDACTED***');
    expect(redactEnvValue('AWS_SECRET_ACCESS_KEY', 'xyz')).toBe('***REDACTED***');
  });

  it('passes through non-secret variables but still scans their values', () => {
    expect(redactEnvValue('NODE_ENV', 'production')).toBe('production');
    expect(redactEnvValue('CONFIG', 'sk-abcdefghijklmnopqrstuvwxyz012345')).toContain('REDACTED');
  });
});

describe('redactObject', () => {
  it('redacts nested sensitive keys', () => {
    const input = { user: 'a', auth: { token: 'super-secret', nested: { password: 'hunter2' } } };
    const output = redactObject(input) as typeof input;
    expect(output.user).toBe('a');
    expect(output.auth.token).toBe('***REDACTED***');
    expect(output.auth.nested.password).toBe('***REDACTED***');
  });

  it('handles arrays and depth limits', () => {
    const input = { items: [{ apiKey: 'abc' }, { value: 'keep' }] };
    const output = redactObject(input) as typeof input;
    expect(output.items[0]?.apiKey).toBe('***REDACTED***');
    expect(output.items[1]?.value).toBe('keep');
  });
});
