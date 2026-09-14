import type { ScanResult } from '@deplyze/scanners';

/** Convert a scan result into a JSON-safe structure (Maps and classes removed). */
export function toJsonResult(result: ScanResult): Record<string, unknown> {
  const graph = result.graph.toJSON();
  return {
    schemaVersion: 1,
    generator: { name: 'deplyze', version: result.diagnostics ? '0.1.0' : '0.1.0' },
    startedAt: result.startedAt,
    finishedAt: result.finishedAt,
    project: {
      name: result.project.name,
      version: result.project.version,
      private: result.project.private,
      manager: result.project.manager,
      root: result.project.root,
      workspaces: result.project.workspaces.map((workspace) => ({
        path: workspace.path,
        name: workspace.name,
        version: workspace.version,
        private: workspace.private,
        declaredCount: workspace.declared.length,
      })),
      lockfiles: result.project.lockfiles,
      warnings: result.project.warnings,
    },
    stats: result.stats,
    summary: result.summary,
    risk: result.risk,
    findings: result.findings,
    dependencies: {
      nodes: graph.nodes.map((node) => ({
        id: node.id,
        name: node.name,
        version: node.version,
        ecosystem: node.ecosystem,
        direct: node.direct,
        dev: node.dev,
        optional: node.optional,
        peer: node.peer,
        depth: node.depth,
        license: node.license,
        deprecated: node.deprecated,
        workspace: node.workspace,
        declaredRange: node.declaredRange,
        integrity: node.integrity,
        resolved: node.resolved,
      })),
      edges: graph.edges,
    },
    diagnostics: result.diagnostics,
  };
}
