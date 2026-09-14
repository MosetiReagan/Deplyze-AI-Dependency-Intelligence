# Architecture

Deplyze is a pnpm monorepo. The central design rule is that the **deterministic core has no
knowledge of the CLI, the reporters, the AI layer or MCP**. Those are output adapters that depend on
the core; the core depends on none of them.

## Packages

| Package               | Responsibility                                                                                                | Depends on                                 |
| --------------------- | ------------------------------------------------------------------------------------------------------------- | ------------------------------------------ |
| `@deplyze/core`       | Domain model, dependency graph, findings, semver helpers, redaction, filesystem safety, logger, typed errors. | —                                          |
| `@deplyze/ecosystems` | Manifest and lockfile parsing, project/workspace detection, normalisation into the core model.                | core                                       |
| `@deplyze/advisories` | OSV client, normalization, CVSS scoring, disk cache, advisory matching.                                       | core                                       |
| `@deplyze/config`     | Zod schema, config discovery and resolution.                                                                  | core                                       |
| `@deplyze/risk`       | Explainable, rule-based scoring.                                                                              | core                                       |
| `@deplyze/scanners`   | The analysis engines and the scan orchestrator.                                                               | core, ecosystems, advisories, config, risk |
| `@deplyze/policies`   | Suppressions and CI policy evaluation.                                                                        | core, config, scanners                     |
| `@deplyze/sbom`       | CycloneDX and SPDX generation.                                                                                | core, scanners                             |
| `@deplyze/reporters`  | Terminal, JSON, Markdown, SARIF, HTML and source-location mapping.                                            | core, scanners                             |
| `@deplyze/ai`         | Provider abstraction, context minimisation, prompt fencing.                                                   | core, config, scanners                     |
| `@deplyze/mcp`        | MCP server and tools.                                                                                         | scanners, policies, sbom                   |
| `apps/cli`            | The `deplyze` binary.                                                                                         | all of the above                           |

Each package is ESM, built with `tsup`, and exposes a single `index.ts` entry point.

## Data flow

```text
loadProject(root)
  └── detect manager + workspaces + lockfiles
  └── parse manifests and lockfiles
  └── build DependencyGraph            (nodes, edges, depth, kinds)

runScan({ root, config })
  ├── RegistryClient.metadataFor(...)   (direct + unknown-license packages)
  ├── OsvClient.queryBatch(...)         (one batch for all npm nodes)
  ├── scanSourceUsage(root)             (imports, requires, scripts, config refs)
  ├── scanners.run(context)             (all scanners, errors isolated per scanner)
  ├── dedupeFindings + summarize
  └── scoreRisk(findings, stats)
       → ScanResult

evaluatePolicy(result)   → exit code
generateSbom(result)     → CycloneDX | SPDX
reporter.render(result)  → terminal | json | markdown | sarif | html
```

## Key invariants

- **The graph is real.** It is built from lockfile resolution, including transitive and duplicate
  versions, and supports cycles.
- **Findings are deterministic.** `createFinding()` derives a stable id from the issue's identity
  (rule + package + version + advisory), never from array position.
- **Scanner failures are isolated.** A scanner that throws is recorded in `diagnostics.scannerErrors`
  and the rest of the analysis is preserved.
- **Unknown is a first-class answer.** When advisory data cannot be retrieved, ids land in
  `diagnostics.unresolvedAdvisories` instead of being dropped silently.
- **Network use is explicit.** `diagnostics.usedNetwork` and `usedCache` record what happened.

## Extension points

- **Ecosystem adapters** implement `LockfileParser` and are registered in `loader.ts`.
- **Scanners** implement `Scanner` and are registered in `defaultScanners()`.
- **Reporters** implement `Reporter` and are registered in `REPORTERS`.
- **AI providers** implement `AiProvider` and are created by `createProvider()`.

See [CONTRIBUTING.md](../CONTRIBUTING.md) for step-by-step instructions.
