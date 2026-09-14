#!/usr/bin/env node
import { buildProgram } from './program.js';

async function main(): Promise<void> {
  const program = buildProgram();
  try {
    await program.parseAsync(process.argv);
  } catch (error) {
    // Commander's exitOverride throws for --help/--version and usage errors.
    const candidate = error as { code?: string; exitCode?: number; message?: string };
    if (candidate?.code === 'commander.helpDisplayed' || candidate?.code === 'commander.version') {
      process.exitCode = 0;
      return;
    }
    if (candidate?.code?.startsWith('commander.')) {
      process.exitCode = typeof candidate.exitCode === 'number' ? candidate.exitCode : 1;
      return;
    }
    process.stderr.write(`${candidate?.message ?? String(error)}\n`);
    process.exitCode = 2;
  }
}

main().catch((error: unknown) => {
  process.stderr.write(`Fatal: ${error instanceof Error ? error.message : String(error)}\n`);
  process.exitCode = 2;
});
