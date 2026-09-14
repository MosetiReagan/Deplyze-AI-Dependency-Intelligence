# deplyze

**AI Dependency Intelligence.** Dependency and software supply-chain auditing for modern
JavaScript/TypeScript applications and AI coding agents.

```bash
npx deplyze scan
```

- Real dependency graphs from npm, pnpm, Yarn and Bun lockfiles (transitive, duplicates, paths).
- Real advisories from [OSV](https://osv.dev), with reproducible CVSS v3 scoring.
- Licenses, outdated packages, deprecated packages, install scripts, typosquats and unused deps.
- Explainable risk scoring where every point traces to a finding.
- CI-friendly: deterministic exit codes (`0` pass, `1` policy violation, `2` error).
- Reports: terminal, JSON, Markdown, SARIF (GitHub code scanning) and HTML; SBOM in CycloneDX and SPDX.
- An MCP server for AI coding agents, including a pre-install package check.
- Optional AI explanations. Deplyze works completely without an LLM.
- Read-only and safe: it never executes package code and never modifies your project.

Full documentation: <https://github.com/deplyze/deplyze#readme>

Licensed under the Apache License 2.0.
