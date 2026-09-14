import { readdir, readFile, stat } from 'node:fs/promises';
import path from 'node:path';

export interface SourceUsage {
  /** Package name -> files that reference it (repo-relative). */
  imported: Map<string, string[]>;
  /** Binaries/commands referenced from package.json scripts. */
  scriptCommands: Set<string>;
  /** Package names mentioned in config files (eslint, tsconfig, etc.). */
  configReferences: Set<string>;
  filesScanned: number;
  bytesScanned: number;
  truncated: boolean;
  /** Dynamic `require(variable)` / computed imports were observed. */
  hasDynamicImports: boolean;
  /** Files that could not be read or parsed. */
  skippedFiles: number;
}

export interface SourceScanOptions {
  maxFiles?: number;
  maxFileBytes?: number;
  maxTotalBytes?: number;
  exclude?: string[];
  extensions?: string[];
  signal?: AbortSignal;
}

const DEFAULT_EXTENSIONS = [
  '.ts',
  '.tsx',
  '.mts',
  '.cts',
  '.js',
  '.jsx',
  '.mjs',
  '.cjs',
  '.vue',
  '.svelte',
  '.astro',
];

const DEFAULT_EXCLUDE = new Set([
  'node_modules',
  '.git',
  'dist',
  'build',
  'out',
  'coverage',
  '.next',
  '.nuxt',
  '.turbo',
  '.cache',
  'vendor',
  '.venv',
  '__pycache__',
  '.deplyze-cache',
]);

/** Files whose contents count as "config usage" for a dependency. */
const CONFIG_FILES = new Set([
  'package.json',
  'tsconfig.json',
  'jsconfig.json',
  'eslint.config.js',
  'eslint.config.mjs',
  'eslint.config.cjs',
  '.eslintrc',
  '.eslintrc.json',
  '.eslintrc.js',
  '.eslintrc.cjs',
  '.eslintrc.yml',
  '.prettierrc',
  '.prettierrc.json',
  '.prettierrc.js',
  'vite.config.ts',
  'vite.config.js',
  'vitest.config.ts',
  'vitest.config.js',
  'jest.config.js',
  'jest.config.ts',
  'rollup.config.js',
  'rollup.config.ts',
  'webpack.config.js',
  'webpack.config.ts',
  'tailwind.config.js',
  'tailwind.config.ts',
  'postcss.config.js',
  'babel.config.js',
  'babel.config.json',
  '.babelrc',
  'next.config.js',
  'next.config.mjs',
  'nuxt.config.ts',
  'svelte.config.js',
  'turbo.json',
  'nx.json',
  'lerna.json',
  '.mocharc.json',
  '.mocharc.js',
  'playwright.config.ts',
  'cypress.config.ts',
]);

const IMPORT_PATTERNS: RegExp[] = [
  // import x from 'pkg' / import 'pkg' / export ... from 'pkg'
  /(?:^|[\s;{(])import\s+(?:[\s\S]*?\sfrom\s+)?['"]([^'"]+)['"]/g,
  /(?:^|[\s;{(])export\s+[\s\S]*?\sfrom\s+['"]([^'"]+)['"]/g,
  /\brequire\s*\(\s*['"]([^'"]+)['"]\s*\)/g,
  /\bimport\s*\(\s*['"]([^'"]+)['"]\s*\)/g,
  /\brequire\.resolve\s*\(\s*['"]([^'"]+)['"]\s*\)/g,
];

const DYNAMIC_PATTERNS: RegExp[] = [/\brequire\s*\(\s*[^'")\s]/g, /\bimport\s*\(\s*[^'")\s]/g];

/** Normalize a module specifier to an npm package name, or undefined. */
export function packageNameFromSpecifier(specifier: string): string | undefined {
  const value = specifier.trim();
  if (value.length === 0) return undefined;
  if (value.startsWith('.') || value.startsWith('/') || value.startsWith('#')) return undefined;
  if (value.startsWith('node:') || value.startsWith('bun:')) return undefined;
  if (value.includes('://')) return undefined;

  if (BUILTINS.has(value)) return undefined;
  if (value.startsWith('@')) {
    const parts = value.split('/');
    if (parts.length < 2) return undefined;
    return `${parts[0]}/${parts[1]}`;
  }
  // Node builtins: `fs`, `path`, `fs/promises` all resolve to a builtin head.
  const head = value.split('/')[0];
  if (head && BUILTINS.has(head)) return undefined;
  return head;
}

const BUILTINS = new Set([
  'assert',
  'async_hooks',
  'buffer',
  'child_process',
  'cluster',
  'console',
  'constants',
  'crypto',
  'dgram',
  'diagnostics_channel',
  'dns',
  'domain',
  'events',
  'fs',
  'http',
  'http2',
  'https',
  'inspector',
  'module',
  'net',
  'os',
  'path',
  'perf_hooks',
  'process',
  'punycode',
  'querystring',
  'readline',
  'repl',
  'stream',
  'string_decoder',
  'sys',
  'timers',
  'tls',
  'trace_events',
  'tty',
  'url',
  'util',
  'v8',
  'vm',
  'wasi',
  'worker_threads',
  'zlib',
  'test',
  'assert/strict',
  'fs/promises',
  'dns/promises',
  'stream/promises',
  'stream/web',
  'timers/promises',
  'util/types',
  'readline/promises',
  'sqlite',
]);

function addReference(map: Map<string, string[]>, pkg: string, file: string): void {
  const list = map.get(pkg);
  if (!list) {
    map.set(pkg, [file]);
    return;
  }
  if (list.length < 20 && !list.includes(file)) list.push(file);
}

/**
 * Build an index of every npm package referenced by the project's source.
 *
 * Scanning is bounded (file count, per-file size, total bytes) so a pathological
 * repository cannot exhaust memory. Files that fail to read are counted, not
 * fatal — a partial index is reported as lower confidence rather than as a
 * false "unused" claim.
 */
export async function scanSourceUsage(root: string, options: SourceScanOptions = {}): Promise<SourceUsage> {
  const maxFiles = options.maxFiles ?? 20_000;
  const maxFileBytes = options.maxFileBytes ?? 2 * 1024 * 1024;
  const maxTotalBytes = options.maxTotalBytes ?? 256 * 1024 * 1024;
  const extensions = new Set(options.extensions ?? DEFAULT_EXTENSIONS);
  const exclude = new Set([...DEFAULT_EXCLUDE, ...(options.exclude ?? [])]);

  const usage: SourceUsage = {
    imported: new Map(),
    scriptCommands: new Set(),
    configReferences: new Set(),
    filesScanned: 0,
    bytesScanned: 0,
    truncated: false,
    hasDynamicImports: false,
    skippedFiles: 0,
  };

  const queue: string[] = [root];
  while (queue.length > 0) {
    if (options.signal?.aborted) break;
    if (usage.filesScanned >= maxFiles || usage.bytesScanned >= maxTotalBytes) {
      usage.truncated = true;
      break;
    }
    const dir = queue.shift() as string;
    let entries;
    try {
      entries = await readdir(dir, { withFileTypes: true });
    } catch {
      continue;
    }
    for (const entry of entries) {
      // Re-check the budget for every file, not just every directory: a single
      // directory can contain thousands of files, and exceeding maxFiles would
      // otherwise be unbounded within one iteration.
      if (usage.filesScanned >= maxFiles || usage.bytesScanned >= maxTotalBytes) {
        usage.truncated = true;
        break;
      }
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        if (exclude.has(entry.name) || (entry.name.startsWith('.') && entry.name !== '.github')) continue;
        queue.push(full);
        continue;
      }
      if (!entry.isFile()) continue;

      const relative = path.relative(root, full).split(path.sep).join('/');
      const isConfig = CONFIG_FILES.has(entry.name);
      const extension = path.extname(entry.name).toLowerCase();
      if (!isConfig && !extensions.has(extension)) continue;

      try {
        const info = await stat(full);
        if (info.size > maxFileBytes) {
          usage.skippedFiles += 1;
          continue;
        }
        const content = await readFile(full, 'utf8');
        usage.filesScanned += 1;
        usage.bytesScanned += content.length;

        if (isConfig) {
          collectConfigReferences(content, entry.name, usage);
        }
        if (extensions.has(extension)) {
          collectImports(content, relative, usage);
        }
      } catch {
        usage.skippedFiles += 1;
      }
    }
  }

  return usage;
}

function collectImports(content: string, relative: string, usage: SourceUsage): void {
  for (const pattern of IMPORT_PATTERNS) {
    pattern.lastIndex = 0;
    let match: RegExpExecArray | null;
    while ((match = pattern.exec(content)) !== null) {
      const specifier = match[1];
      if (!specifier) continue;
      const pkg = packageNameFromSpecifier(specifier);
      if (pkg) addReference(usage.imported, pkg, relative);
    }
  }
  for (const pattern of DYNAMIC_PATTERNS) {
    pattern.lastIndex = 0;
    if (pattern.test(content)) {
      usage.hasDynamicImports = true;
      break;
    }
  }
}

function collectConfigReferences(content: string, filename: string, usage: SourceUsage): void {
  if (filename === 'package.json') {
    try {
      const manifest = JSON.parse(content) as {
        scripts?: Record<string, string>;
        dependencies?: Record<string, string>;
        devDependencies?: Record<string, string>;
        optionalDependencies?: Record<string, string>;
        peerDependencies?: Record<string, string>;
        eslintConfig?: unknown;
        prettier?: unknown;
        jest?: unknown;
      };
      for (const command of Object.values(manifest.scripts ?? {})) {
        for (const token of tokenizeCommand(command)) usage.scriptCommands.add(token);
      }
      // A dependency declared in package.json is not evidence of *use*, but
      // inline config blocks (eslintConfig, jest, prettier) are.
      if (manifest.eslintConfig) collectQuotedReferences(content, usage);
      if (manifest.jest) collectQuotedReferences(content, usage);
      if (manifest.prettier) collectQuotedReferences(content, usage);
    } catch {
      /* malformed package.json is reported elsewhere */
    }
    return;
  }
  collectQuotedReferences(content, usage);
}

/**
 * Collect bare package-like strings from a config file.
 *
 * Config files reference plugins by name (`"plugin:react/recommended"`,
 * `require.resolve("eslint-plugin-x")`), which is real evidence of use even
 * though it is not an `import` statement.
 */
function collectQuotedReferences(content: string, usage: SourceUsage): void {
  const pattern = /['"](@?[\w][\w./-]*)['"]/g;
  let match: RegExpExecArray | null;
  while ((match = pattern.exec(content)) !== null) {
    const raw = match[1];
    if (!raw) continue;
    const normalized = raw
      .replace(/^plugin:/, '')
      .replace(/^extends:/, '')
      .replace(/\/recommended$/, '')
      .replace(/\/all$/, '');
    if (normalized.length < 2) continue;
    if (normalized.includes('://') || normalized.startsWith('.')) continue;
    usage.configReferences.add(normalized);
  }
}

/**
 * Tokenize a package.json script into candidate command names.
 *
 * Handles `&&`, `||`, pipes, `npx`/`pnpm exec`/`yarn` prefixes and flags so
 * that `"eslint . --fix"` yields `eslint`.
 */
export function tokenizeCommand(command: string): string[] {
  const tokens: string[] = [];
  const segments = command.split(/&&|\|\||;|\|/);
  for (const segment of segments) {
    const parts = segment.trim().split(/\s+/).filter(Boolean);
    let index = 0;
    while (index < parts.length) {
      const part = parts[index] as string;
      if (part === 'npx' || part === 'pnpx' || part === 'bunx') {
        index += 1;
        continue;
      }
      if (part === 'pnpm' || part === 'yarn' || part === 'npm' || part === 'bun') {
        index += 1;
        const sub = parts[index];
        if (sub === 'exec' || sub === 'dlx' || sub === 'run' || sub === 'run-script') index += 1;
        continue;
      }
      if (part === 'cross-env' || part === 'env') {
        index += 1;
        while (index < parts.length && (parts[index] as string).includes('=')) index += 1;
        continue;
      }
      if (part.startsWith('-')) {
        index += 1;
        continue;
      }
      tokens.push(part);
      break;
    }
  }
  return tokens;
}
