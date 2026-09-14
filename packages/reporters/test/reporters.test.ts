import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import {
  getReporter,
  locateDependency,
  renderMarkdown,
  renderSarif,
  renderTerminal,
  REPORTERS,
  toJsonResult,
} from '../src/index.js';
import { makeFinding, makeResult } from '../../../test/helpers.js';

const dirs: string[] = [];
afterEach(async () => {
  await Promise.all(dirs.splice(0).map((dir) => rm(dir, { recursive: true, force: true })));
});

const finding = makeFinding({
  package: 'lodash',
  version: '4.17.20',
  advisoryId: 'GHSA-test-1111-2222',
  severity: 'high',
  title: 'Prototype pollution in lodash',
  description: 'lodash is affected by GHSA-test-1111-2222.',
  remediation: {
    summary: 'Upgrade lodash to 4.17.21.',
    command: 'npm install lodash@^4.17.21',
    upgrades: [{ package: 'lodash', from: '4.17.20', to: '4.17.21', breaking: false }],
  },
});

const result = makeResult({ findings: [finding] });

describe('getReporter', () => {
  it('resolves every advertised format and rejects unknown ones', () => {
    expect(REPORTERS.map((reporter) => reporter.id)).toEqual([
      'terminal',
      'json',
      'markdown',
      'sarif',
      'html',
    ]);
    expect(getReporter('sarif').extension).toBe('sarif');
    expect(() => getReporter('nope')).toThrow();
  });
});

describe('json reporter', () => {
  it('serializes the scan into a JSON-safe structure', () => {
    const payload = toJsonResult(result) as Record<string, unknown>;
    expect(payload.schemaVersion).toBe(1);
    expect((payload.findings as unknown[]).length).toBe(1);
    const dependencies = payload.dependencies as { nodes: unknown[]; edges: unknown[] };
    expect(dependencies.nodes.length).toBe(3);
    expect(dependencies.edges.length).toBe(2);
  });
});

describe('markdown reporter', () => {
  it('renders a reviewable report with findings and remediation', () => {
    const markdown = renderMarkdown(result);
    expect(markdown).toContain('# Deplyze');
    expect(markdown).toContain('Prototype pollution in lodash');
    expect(markdown).toContain('npm install lodash@^4.17.21');
    expect(markdown).toContain('GHSA-test-1111-2222');
  });
});

describe('sarif reporter', () => {
  it('produces a valid SARIF 2.1.0 document with one result per finding', () => {
    const sarif = JSON.parse(renderSarif(result));
    expect(sarif.version).toBe('2.1.0');
    const run = sarif.runs[0];
    expect(run.tool.driver.name).toBe('Deplyze');
    expect(run.results).toHaveLength(1);
    expect(run.results[0].ruleId).toBe('security/vulnerability/GHSA-test-1111-2222');
    expect(run.results[0].level).toBe('error');
    expect(run.results[0].properties.severity).toBe('high');
    expect(run.results[0].properties.securitySeverity).toBe('8.0');
    expect(run.tool.driver.rules).toHaveLength(1);
  });

  it('maps severities to the three SARIF levels', () => {
    const critical = JSON.parse(
      renderSarif(makeResult({ findings: [makeFinding({ severity: 'critical', title: 'C' })] })),
    );
    const medium = JSON.parse(
      renderSarif(makeResult({ findings: [makeFinding({ severity: 'medium', title: 'M' })] })),
    );
    const low = JSON.parse(
      renderSarif(makeResult({ findings: [makeFinding({ severity: 'low', title: 'L' })] })),
    );
    expect(critical.runs[0].results[0].level).toBe('error');
    expect(medium.runs[0].results[0].level).toBe('warning');
    expect(low.runs[0].results[0].level).toBe('note');
  });

  it('attaches a real manifest location when it can find one', async () => {
    const dir = await mkdtemp(path.join(os.tmpdir(), 'deplyze-sarif-'));
    dirs.push(dir);
    await writeFile(
      path.join(dir, 'package.json'),
      ['{', '  "name": "app",', '  "dependencies": {', '    "lodash": "^4.17.0"', '  }', '}'].join('\n'),
    );
    const located = makeResult({ findings: [finding], root: dir });
    located.project.workspaces[0]!.declared.push({
      name: 'lodash',
      range: '^4.17.0',
      kind: 'prod',
      manifest: 'package.json',
    });
    const location = locateDependency(dir, located, 'lodash');
    expect(location?.file).toBe('package.json');
    expect(location?.line).toBe(4);
    const sarif = JSON.parse(renderSarif(located));
    expect(sarif.runs[0].results[0].locations[0].physicalLocation.region.startLine).toBe(4);
  });

  it('marks the invocation unsuccessful when a scanner failed', () => {
    const failed = makeResult({ findings: [finding] });
    failed.diagnostics.scannerErrors.push({ scanner: 'outdated/versions', message: 'boom' });
    const sarif = JSON.parse(renderSarif(failed));
    expect(sarif.runs[0].invocations[0].executionSuccessful).toBe(false);
    expect(sarif.runs[0].invocations[0].toolExecutionNotifications[0].message.text).toContain('boom');
  });
});

describe('terminal reporter', () => {
  it('renders the project summary without ANSI codes when color is off', () => {
    const output = renderTerminal(result, { color: 'never' });
    expect(output).toContain('fixture-app');
    expect(output).not.toContain('\u001b[');
    expect(output).toContain('Prototype pollution in lodash');
  });
});
