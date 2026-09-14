import { describe, expect, it } from 'vitest';
import { parseCvssVector, scoreCvssVector, severityFromCvss } from '../src/index.js';

describe('parseCvssVector', () => {
  it('parses a v3.1 vector into metrics', () => {
    const metrics = parseCvssVector('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H');
    expect(metrics).toEqual({ AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'H', I: 'H', A: 'H' });
  });

  it('rejects non-v3 vectors', () => {
    expect(parseCvssVector('CVSS:4.0/AV:N')).toBeUndefined();
    expect(parseCvssVector('not a vector')).toBeUndefined();
  });
});

describe('scoreCvssVector', () => {
  it('computes the FIRST reference score for a critical vector', () => {
    const result = scoreCvssVector('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H');
    expect(result?.score).toBe(9.8);
    expect(result?.version).toBe('3.1');
  });

  it('computes a scope-changed score correctly', () => {
    // Published example: CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N = 6.1
    const result = scoreCvssVector('CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N');
    expect(result?.score).toBe(6.1);
  });

  it('reports a zero score when impact is none', () => {
    const result = scoreCvssVector('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N');
    expect(result?.score).toBe(0);
  });

  it('returns undefined for malformed or unsupported vectors', () => {
    expect(scoreCvssVector('CVSS:4.0/AV:N/AC:L')).toBeUndefined();
    expect(scoreCvssVector('CVSS:3.1/AV:N/AC:L')).toBeUndefined();
    expect(scoreCvssVector('nope')).toBeUndefined();
  });
});

describe('severityFromCvss', () => {
  it('maps scores onto the shared severity bands', () => {
    expect(severityFromCvss(9.8)).toBe('critical');
    expect(severityFromCvss(7.0)).toBe('high');
    expect(severityFromCvss(4.0)).toBe('medium');
    expect(severityFromCvss(0.1)).toBe('low');
    expect(severityFromCvss(0)).toBe('info');
  });
});
