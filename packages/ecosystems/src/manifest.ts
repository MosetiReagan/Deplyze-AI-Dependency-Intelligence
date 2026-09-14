import { z } from 'zod';
import { DeplyzeError, ErrorCode } from '@deplyze/core';
import type { DependencyDeclaration, DependencyKind } from '@deplyze/core';

/**
 * Lenient manifest schema.
 *
 * Real-world `package.json` files contain far more than the spec defines, so
 * every unknown key is preserved via `.passthrough()`. Validation errors are
 * only raised for structurally broken documents (e.g. a string where an object
 * is required).
 */
const stringMap = z.record(z.string(), z.string());

export const packageJsonSchema = z
  .object({
    name: z.string().min(1).max(214).optional(),
    version: z.string().optional(),
    private: z.boolean().optional(),
    type: z.string().optional(),
    license: z.union([z.string(), z.record(z.string(), z.unknown())]).optional(),
    licenses: z.array(z.object({ type: z.string().optional(), url: z.string().optional() })).optional(),
    engines: stringMap.optional(),
    scripts: stringMap.optional(),
    dependencies: stringMap.optional(),
    devDependencies: stringMap.optional(),
    optionalDependencies: stringMap.optional(),
    peerDependencies: stringMap.optional(),
    peerDependenciesMeta: z.record(z.string(), z.object({ optional: z.boolean().optional() })).optional(),
    bundleDependencies: z.array(z.string()).optional(),
    bundledDependencies: z.array(z.string()).optional(),
    overrides: z.record(z.string(), z.unknown()).optional(),
    resolutions: z.record(z.string(), z.unknown()).optional(),
    workspaces: z
      .union([z.array(z.string()), z.object({ packages: z.array(z.string()) }).passthrough()])
      .optional(),
    packageManager: z.string().optional(),
  })
  .passthrough();

export type PackageJson = z.infer<typeof packageJsonSchema>;

export function parsePackageJson(raw: string, sourcePath: string): PackageJson {
  let data: unknown;
  try {
    data = JSON.parse(raw);
  } catch (error) {
    throw new DeplyzeError(
      ErrorCode.DEPLYZE_E_MANIFEST_PARSE,
      `Could not parse ${sourcePath}: invalid JSON.`,
      {
        hint: 'Fix the JSON syntax error and re-run Deplyze.',
        cause: error,
      },
    );
  }
  const result = packageJsonSchema.safeParse(data);
  if (!result.success) {
    const issue = result.error.issues[0];
    const where = issue?.path.join('.') ?? '<root>';
    throw new DeplyzeError(
      ErrorCode.DEPLYZE_E_MANIFEST_PARSE,
      `Could not parse ${sourcePath}: ${issue?.message ?? 'invalid structure'} (at ${where}).`,
      { hint: 'Ensure dependency fields map package names to version range strings.' },
    );
  }
  return result.data;
}

const KINDS: Array<{ field: keyof PackageJson; kind: DependencyKind }> = [
  { field: 'dependencies', kind: 'prod' },
  { field: 'devDependencies', kind: 'dev' },
  { field: 'optionalDependencies', kind: 'optional' },
  { field: 'peerDependencies', kind: 'peer' },
];

export function declarationsOf(manifest: PackageJson, manifestPath: string): DependencyDeclaration[] {
  const declarations: DependencyDeclaration[] = [];
  const seen = new Set<string>();
  for (const { field, kind } of KINDS) {
    const map = manifest[field] as Record<string, string> | undefined;
    if (!map) continue;
    for (const [name, range] of Object.entries(map)) {
      const key = `${name}:${kind}`;
      if (seen.has(key)) continue;
      seen.add(key);
      declarations.push({ name, range, kind, manifest: manifestPath });
    }
  }
  return declarations;
}

export function workspacePatterns(manifest: PackageJson): string[] {
  const workspaces = manifest.workspaces;
  if (!workspaces) return [];
  if (Array.isArray(workspaces)) return workspaces;
  return Array.isArray(workspaces.packages) ? workspaces.packages : [];
}

export function licenseOf(manifest: PackageJson): string | undefined {
  if (typeof manifest.license === 'string') return manifest.license;
  if (Array.isArray(manifest.licenses)) {
    const types = manifest.licenses.map((entry) => entry.type).filter((t): t is string => !!t);
    if (types.length > 0) return types.join(' OR ');
  }
  if (manifest.license && typeof manifest.license === 'object') {
    const type = (manifest.license as Record<string, unknown>).type;
    if (typeof type === 'string') return type;
  }
  return undefined;
}
