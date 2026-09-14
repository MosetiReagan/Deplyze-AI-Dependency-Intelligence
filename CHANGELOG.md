# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0]

The first public release of Deplyze.

### Added

- **CLI** (`deplyze`): `scan`, `audit`/`analyze`/`analyse`, `security`, `outdated`, `unused`,
  `duplicates`, `licenses`, `graph`, `package`, `guard`, `explain`, `upgrade-plan`, `fix`,
  `remediate`, `ai-review`, `sbom`, `policy`, `ci`, `report`, `mcp`, `doctor`, `version`.
- **Ecosystems**: npm (`package-lock.json`), pnpm (`pnpm-lock.yaml` v6/v9), Yarn v1 and Berry
  lockfiles, and Bun (`bun.lock`/`bun.lockb`). npm/pnpm/yarn workspaces and monorepos.
- **Dependency graph**: transitive resolution, dependency paths, reverse dependencies, duplicate
  versions, depth statistics, and workspace boundaries.
- **Vulnerability intelligence**: OSV batch queries, OSV/GHSA/CVE normalization, CVSS v3.0/v3.1
  scoring per the FIRST specification, offline advisory cache, and version-range matching.
- **Scanners**: vulnerabilities, license policy, duplicates, outdated, health (deprecated/stale),
  lifecycle scripts (inspected, never executed), typosquat/new-package supply-chain signals, and
  likely-unused dependencies.
- **Reports**: terminal, JSON, Markdown, SARIF 2.1.0 (GitHub code scanning) and standalone HTML.
- **SBOM**: CycloneDX 1.5 and SPDX 2.3, with purls, hashes, licenses and dependency relationships.
- **Risk scoring**: six explainable category scores and a weighted overall health score; every
  deduction cites its rule and findings.
- **Policy engine**: severity thresholds, vulnerability ceilings, denied licenses/packages,
  deprecation and install-script rules, with reasoned and expiring suppressions.
- **Configuration**: `.deplyze.yml`/`.yaml`/`.json` and `deplyze.config.{js,mjs,cjs,ts}` with a
  validated schema, plus `--config` and `--offline`/`--no-network`.
- **AI (optional)**: provider abstraction (OpenAI-compatible, Anthropic, Gemini, Ollama, generic
  HTTP), context minimisation, secret redaction, untrusted-data fencing, and a deterministic
  fallback for every AI feature.
- **MCP server**: ten tools for AI coding agents, including the pre-install `deplyze_package`
  evidence workflow.
- **Security controls**: no code execution, no arbitrary shell, path-traversal guards, SSRF-safe
  registry URLs, resource limits, secret redaction and a read-only design throughout.
- **Developer experience**: deterministic exit codes (`0`/`1`/`2`), SARIF for GitHub code scanning,
  structured terminal output, and `pnpm lint && pnpm typecheck && pnpm test && pnpm build` CI.

[Unreleased]: https://github.com/deplyze/deplyze/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/deplyze/deplyze/releases/tag/v0.1.0
