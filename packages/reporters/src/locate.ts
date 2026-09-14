import { readFileSync } from 'node:fs';
import path from 'node:path';
import type { ScanResult } from '@deplyze/scanners';

export interface SourceLocation {
  file: string;
  line: number;
  column: number;
  /** The manifest line, for the SARIF snippet. */
  snippet?: string;
}

/**
 * Locate the declaration of a dependency inside the manifest that declares it.
 *
 * Used to give SARIF results a real file/line so GitHub code scanning can
 * annotate the pull request rather than reporting a location-less alert.
 */
export function locateDependency(
  root: string,
  result: ScanResult,
  packageName: string,
): SourceLocation | undefined {
  const workspaces = result.project.workspaces;
  for (const workspace of workspaces) {
    const declaration = workspace.declared.find((entry) => entry.name === packageName);
    if (!declaration) continue;
    const file = declaration.manifest;
    try {
      const content = readFileSync(path.join(root, file), 'utf8');
      const lines = content.split(/\r?\n/);
      const escaped = packageName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      const pattern = new RegExp(`"${escaped}"\\s*:`);
      for (let index = 0; index < lines.length; index += 1) {
        const line = lines[index] as string;
        const match = line.match(pattern);
        if (match && match.index !== undefined) {
          return {
            file,
            line: index + 1,
            column: match.index + 1,
            snippet: line.trim(),
          };
        }
      }
      return { file, line: 1, column: 1 };
    } catch {
      return { file, line: 1, column: 1 };
    }
  }
  return undefined;
}
