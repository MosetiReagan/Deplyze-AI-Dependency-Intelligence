import { access, mkdir, readdir, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileExists } from '@deplyze/core';
import { loadConfig } from '@deplyze/config';
import { OsvClient } from '@deplyze/advisories';
import { createContext, type GlobalFlags } from '../context.js';
import { printHeading } from '../output.js';

export interface DoctorFlags extends GlobalFlags {
  network?: boolean;
}

interface Check {
  name: string;
  status: 'ok' | 'warn' | 'fail' | 'skip';
  detail: string;
}

export async function doctorCommand(flags: DoctorFlags): Promise<number> {
  const checks: Check[] = [];
  const context = await createContext(flags);
  const root = context.root;

  // Runtime
  const major = Number(process.versions.node.split('.')[0]);
  checks.push({
    name: 'Node.js',
    status: major >= 20 ? 'ok' : 'fail',
    detail: `v${process.versions.node}${major >= 20 ? '' : ' — Deplyze requires Node.js 20 or newer'}`,
  });

  checks.push({
    name: 'Platform',
    status: 'ok',
    detail: `${process.platform} ${process.arch}`,
  });

  // Project
  const hasManifest = await fileExists(path.join(root, 'package.json'));
  checks.push({
    name: 'package.json',
    status: hasManifest ? 'ok' : 'fail',
    detail: hasManifest ? 'found' : `not found in ${root}`,
  });

  const lockfiles = ['pnpm-lock.yaml', 'package-lock.json', 'yarn.lock', 'bun.lock', 'bun.lockb'];
  const found: string[] = [];
  for (const lockfile of lockfiles) {
    if (await fileExists(path.join(root, lockfile))) found.push(lockfile);
  }
  checks.push({
    name: 'Lockfile',
    status: found.length > 0 ? 'ok' : 'warn',
    detail:
      found.length > 0
        ? found.join(', ')
        : 'none found — transitive dependencies and exact versions cannot be resolved',
  });

  // Configuration
  try {
    const config = await loadConfig(root, flags.config ? { explicitPath: flags.config } : {});
    checks.push({
      name: 'Configuration',
      status: config.warnings.length > 0 ? 'warn' : 'ok',
      detail: config.configPath
        ? `${path.relative(root, config.configPath)}${config.warnings.length > 0 ? ` (${config.warnings.length} warning(s))` : ''}`
        : 'no config file; using defaults',
    });
  } catch (error) {
    checks.push({
      name: 'Configuration',
      status: 'fail',
      detail: error instanceof Error ? error.message : String(error),
    });
  }

  // Cache directory writability
  const cacheDir = path.resolve(root, context.config.scan.cache.directory);
  try {
    await mkdir(cacheDir, { recursive: true });
    const probe = path.join(cacheDir, '.deplyze-write-probe');
    await writeFile(probe, 'ok', 'utf8');
    await access(probe);
    await rm(probe, { force: true });
    let entries = 0;
    try {
      entries = (await readdir(cacheDir)).filter((name) => name.endsWith('.json')).length;
    } catch {
      /* ignore */
    }
    checks.push({
      name: 'Cache',
      status: 'ok',
      detail: `${path.relative(root, cacheDir) || cacheDir} writable, ${entries} cached record(s)`,
    });
  } catch (error) {
    checks.push({
      name: 'Cache',
      status: 'warn',
      detail: `not writable (${error instanceof Error ? error.message : String(error)}) — scans will not be cached`,
    });
  }

  // Network
  if (context.config.scan.offline) {
    checks.push({ name: 'Advisory source', status: 'skip', detail: 'offline mode enabled' });
    checks.push({ name: 'Registry', status: 'skip', detail: 'offline mode enabled' });
  } else {
    const osv = new OsvClient({
      cacheDirectory: `${cacheDir}/advisories`,
      logger: context.logger,
      retries: 0,
    });
    try {
      await osv.fetchVulnerability('GHSA-5xrq-8626-4rwp');
      checks.push({ name: 'Advisory source', status: 'ok', detail: 'api.osv.dev reachable' });
    } catch (error) {
      checks.push({
        name: 'Advisory source',
        status: 'warn',
        detail: `api.osv.dev unreachable (${error instanceof Error ? error.message : String(error)}) — vulnerability findings will be unavailable`,
      });
    }
    try {
      const response = await fetch('https://registry.npmjs.org/-/ping', {
        signal: AbortSignal.timeout(8000),
      });
      checks.push({
        name: 'Registry',
        status: response.ok ? 'ok' : 'warn',
        detail: `registry.npmjs.org responded HTTP ${response.status}`,
      });
    } catch (error) {
      checks.push({
        name: 'Registry',
        status: 'warn',
        detail: `registry.npmjs.org unreachable (${error instanceof Error ? error.message : String(error)})`,
      });
    }
  }

  // AI
  checks.push({
    name: 'AI features',
    status: 'ok',
    detail: context.config.ai.enabled
      ? `enabled (provider: ${context.config.ai.provider})`
      : 'disabled — Deplyze is fully functional without AI',
  });

  checks.push({ name: 'Home directory', status: 'ok', detail: os.homedir() });

  const failed = checks.filter((check) => check.status === 'fail');
  if (flags.format === 'json' || flags.json) {
    process.stdout.write(`${JSON.stringify({ checks, ok: failed.length === 0 }, null, 2)}\n`);
  } else {
    printHeading('Deplyze doctor');
    for (const check of checks) {
      const badge =
        check.status === 'ok'
          ? 'OK  '
          : check.status === 'warn'
            ? 'WARN'
            : check.status === 'skip'
              ? 'SKIP'
              : 'FAIL';
      process.stdout.write(`  ${badge}  ${check.name.padEnd(16)} ${check.detail}\n`);
    }
    process.stdout.write(
      `\n${failed.length === 0 ? 'Environment looks healthy.' : `${failed.length} check(s) failed.`}\n`,
    );
  }
  return failed.length === 0 ? 0 : 2;
}
