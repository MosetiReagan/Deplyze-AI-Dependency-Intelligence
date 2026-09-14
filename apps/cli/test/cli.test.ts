import path from 'node:path';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { buildProgram } from '../src/program.js';

/**
 * Run the CLI in-process against vitest's source aliases. `--no-network` keeps
 * every scan hermetic: no registry, no advisory calls, deterministic output.
 */
async function runCli(
  args: string[],
): Promise<{ code: number; stdout: string; stderr: string; threw?: unknown }> {
  const out: string[] = [];
  const err: string[] = [];
  const outSpy = vi.spyOn(process.stdout, 'write').mockImplementation((chunk: unknown) => {
    out.push(String(chunk));
    return true;
  });
  const errSpy = vi.spyOn(process.stderr, 'write').mockImplementation((chunk: unknown) => {
    err.push(String(chunk));
    return true;
  });
  const previous = process.exitCode;
  process.exitCode = 0;
  let threw: unknown;
  try {
    await buildProgram().parseAsync(['node', 'deplyze', ...args]);
  } catch (error) {
    threw = error;
  }
  let code = typeof process.exitCode === 'number' ? process.exitCode : 0;
  // Mirror apps/cli/src/bin.ts: commander's exitOverride throws for usage
  // errors and --help/--version; map those to their documented exit codes.
  if (threw) {
    const candidate = threw as { code?: string; exitCode?: number };
    if (candidate.code?.startsWith('commander.')) code = candidate.exitCode ?? 1;
  }
  outSpy.mockRestore();
  errSpy.mockRestore();
  process.exitCode = previous;
  return { code, stdout: out.join(''), stderr: err.join(''), ...(threw ? { threw } : {}) };
}

const fixture = (name: string) => path.resolve('fixtures', name);

afterEach(() => {
  vi.restoreAllMocks();
});

describe('deplyze version', () => {
  it('prints version information and exits 0', async () => {
    const { code, stdout } = await runCli(['version']);
    expect(code).toBe(0);
    expect(stdout).toContain('deplyze 0.1.0');
    expect(stdout).toContain('node');
  });
});

describe('deplyze scan', () => {
  it('scans a real fixture in offline mode and exits 0 when the policy passes', async () => {
    const { code, stdout } = await runCli([
      'scan',
      '--path',
      fixture('gpl-project'),
      '--no-network',
      '--no-policy',
    ]);
    expect(code).toBe(0);
    expect(stdout).toContain('gpl-project');
  });

  it('emits machine-readable JSON', async () => {
    const { code, stdout } = await runCli([
      'scan',
      '--path',
      fixture('duplicate-project'),
      '--no-network',
      '--format',
      'json',
    ]);
    expect(code).toBe(0);
    const payload = JSON.parse(stdout) as Record<string, unknown>;
    expect(payload.schemaVersion).toBe(1);
    expect(payload.project).toBeDefined();
    expect(Array.isArray(payload.findings)).toBe(true);
  });

  it('emits valid SARIF', async () => {
    const { stdout } = await runCli([
      'scan',
      '--path',
      fixture('duplicate-project'),
      '--no-network',
      '--format',
      'sarif',
    ]);
    const sarif = JSON.parse(stdout) as {
      version: string;
      runs: Array<{ tool: { driver: { name: string } } }>;
    };
    expect(sarif.version).toBe('2.1.0');
    expect(sarif.runs[0]?.tool.driver.name).toBe('Deplyze');
  });

  it('returns exit code 1 when a finding crosses the configured threshold', async () => {
    const { code } = await runCli([
      'scan',
      '--path',
      fixture('duplicate-project'),
      '--no-network',
      '--fail-on',
      'low',
      '--quiet',
    ]);
    expect(code).toBe(1);
  });

  it('never fails on findings when --no-policy is passed', async () => {
    const { code } = await runCli([
      'scan',
      '--path',
      fixture('duplicate-project'),
      '--no-network',
      '--fail-on',
      'low',
      '--no-policy',
      '--quiet',
    ]);
    expect(code).toBe(0);
  });

  it('rejects an invalid severity with a usage error', async () => {
    const { code, stderr } = await runCli(['scan', '--severity', 'gigantic', '--no-network']);
    expect(code).toBe(2);
    expect(stderr).toContain('Unknown severity');
  });

  it('fails safely on a malformed lockfile instead of trusting a partial graph', async () => {
    const { code, stderr } = await runCli(['scan', '--path', fixture('malformed-lockfile'), '--no-network']);
    expect(code).toBe(2);
    expect(stderr).toContain('Could not parse package-lock.json');
    expect(stderr).toContain('DEPLYZE_E_LOCKFILE_PARSE');
  });

  it('analyses a pnpm workspace monorepo', async () => {
    const { code, stdout } = await runCli([
      'scan',
      '--path',
      fixture('monorepo'),
      '--no-network',
      '--no-policy',
      '--format',
      'json',
    ]);
    const payload = JSON.parse(stdout) as {
      project: { manager: string; workspaces: unknown[] };
      stats: { totalNodes: number };
    };
    expect(code).toBe(0);
    expect(payload.project.manager).toBe('pnpm');
    expect(payload.project.workspaces.length).toBeGreaterThan(1);
    expect(payload.stats.totalNodes).toBeGreaterThan(1);
  });

  it('reports a missing project directory without a stack trace', async () => {
    const { code, stderr } = await runCli(['scan', '--path', fixture('does-not-exist'), '--no-network']);
    expect(code).toBe(2);
    expect(stderr).toMatch(/No package\.json found|not found/);
    expect(stderr).not.toContain('at ');
  });
});

describe('deplyze ci', () => {
  it('runs in CI mode with a deterministic exit code', async () => {
    const { code, stdout } = await runCli([
      'ci',
      '--path',
      fixture('duplicate-project'),
      '--no-network',
      '--format',
      'json',
      '--fail-on',
      'low',
    ]);
    expect(code).toBe(1);
    expect(stdout.length).toBeGreaterThan(0);
  });
});

describe('deplyze graph', () => {
  it('prints graph statistics', async () => {
    const { code, stdout } = await runCli(['graph', '--path', fixture('monorepo'), '--no-network']);
    expect(code).toBe(0);
    expect(stdout.length).toBeGreaterThan(0);
  });
});

describe('deplyze policy', () => {
  it('evaluates policy and reports pass/fail', async () => {
    const { code, stdout } = await runCli(['policy', '--path', fixture('gpl-project'), '--no-network']);
    expect([0, 1]).toContain(code);
    expect(stdout.toLowerCase()).toContain('policy');
  });
});

describe('unknown commands', () => {
  it('fail with a commander exit code', async () => {
    const { code } = await runCli(['definitely-not-a-command']);
    expect(code).toBeGreaterThan(0);
  });
});
