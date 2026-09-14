import { describe, expect, it } from 'vitest';
import { detectTyposquat, typosquatFindings } from '../src/index.js';

describe('detectTyposquat', () => {
  it('flags a single-character variant of a popular package', () => {
    const signal = detectTyposquat({ name: 'expreess' });
    expect(signal?.target).toBe('express');
    expect(signal?.confidence).toBe('medium');
    expect(signal?.similarity).toBeGreaterThan(0.85);
    expect(signal?.recommendedAction).toContain('express');
  });

  it('flags a transposition', () => {
    expect(detectTyposquat({ name: 'lodahs' })?.target).toBe('lodash');
  });

  it('does not flag the legitimate package itself', () => {
    expect(detectTyposquat({ name: 'express' })).toBeUndefined();
    expect(detectTyposquat({ name: 'react' })).toBeUndefined();
  });

  it('does not flag short names or unrelated names', () => {
    expect(detectTyposquat({ name: 'fs' })).toBeUndefined();
    expect(detectTyposquat({ name: 'completely-unrelated-package-name' })).toBeUndefined();
  });

  it('treats an allowlisted name as legitimate', () => {
    expect(detectTyposquat({ name: 'expreess' }, { allowlist: ['expreess'] })).toBeUndefined();
  });

  it('never asserts malicious intent', () => {
    const signal = detectTyposquat({ name: 'expreess' });
    expect(signal?.reason).toContain('differs from');
    expect(signal?.reason.toLowerCase()).not.toContain('malicious');
  });

  it('produces an evidence-backed finding with a confidence level', () => {
    const findings = typosquatFindings([detectTyposquat({ name: 'expreess' })!]);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.category).toBe('supply-chain');
    expect(findings[0]?.confidence).toBe('medium');
    expect(findings[0]?.evidence[0]?.message).toContain('Similarity score');
    expect(findings[0]?.remediation?.steps?.length).toBeGreaterThan(0);
  });
});
