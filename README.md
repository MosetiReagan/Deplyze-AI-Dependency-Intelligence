# Deplyze — AI Dependency Intelligence

Deplyze is an open-source dependency intelligence and software supply-chain auditing platform for
modern JavaScript and TypeScript applications, and for the AI coding agents that now write a lot of
them.

It understands a project's real dependency graph (not just the direct dependencies), matches it
against real advisory data, and reports security exposure, package health, licensing, supply-chain
signals, outdated packages, duplicate versions and likely-unused dependencies — with **evidence for
every claim** and an **explainable risk score**.

```bash
npx deplyze scan
```

> **Status:** early, but real. The npm/pnpm/yarn/bun analysis path is complete and tested. Deplyze
> never executes package code, never installs anything, and never modifies your project. See
> [Roadmap](#roadmap) for what is deliberately not implemented yet.

---

## Why Deplyze exists

`npm audit` answers one question: "are there known advisories for my installed versions?" That is
necessary but not sufficient. Real dependency risk lives in the gaps around that question:

- A vulnerable _transitive_ package, with no indication of which direct dependency pulled it in.
- A package that was deprecated two years ago but still installs cleanly.
- A name that differs from a popular package by one character — a classic typosquat.
- A `postinstall` script that pipes a network download into a shell.
- A license that is incompatible with how you ship your product.
- Three versions of the same library bloating your bundle.
- A dependency nobody imports any more.
- A brand-new package that an AI agent added because the name "looked right".

Deplyze is built around a simple idea: **the dependency intelligence layer between developers,
repositories, CI/CD systems and AI coding agents.**

## Principles

1. **Security first.** Deplyze is security-sensitive software and treats itself that way.
2. **Read-only by default.** It analyses; it does not install, upgrade, or edit anything.
3. **No arbitrary code execution.** Lifecycle scripts are inspected as text, never run.
4. **Deterministic core.** The same inputs produce the same findings and the same exit code.
5. **AI is optional, never required.** Every command works with `ai.enabled: false`.
6. **No fabricated data.** No invented vulnerabilities, no made-up CVSS scores, no fake versions.
7. **Evidence-based findings.** Every finding carries the evidence that produced it.
8. **Explainable risk.** Every point deducted from a score maps to a rule and a finding.
9. **CI/CD friendly.** Stable output formats and deterministic exit codes.
10. **AI-agent friendly.** A first-class MCP server.
11. **Offline wherever possible.** Cached advisories and registry metadata, plus `--offline`.
12. **Production-grade engineering.** Strict TypeScript, tests, lint, typed errors, resource limits.
13. **Extensible.** Ecosystem adapters, scanners, reporters and policies are separate packages.
14. **Fast enough for real repositories.** Bounded concurrency, caching, and hard resource limits.

When Deplyze cannot verify something, it says **unknown** instead of guessing.

## Installation

Node.js 20 or newer is required.

```bash
# one-off
npx deplyze@latest scan

# or install it
npm install -g deplyze
pnpm add -g deplyze

# from source
git clone https://github.com/deplyze/deplyze.git
cd deplyze
pnpm install
pnpm build
node apps/cli/dist/bin.js scan --path /path/to/project
```

## Quick start

```bash
cd my-app
npx deplyze scan
```

```text
Deplyze — AI Dependency Intelligence

  Project:     my-app@1.0.0
  Ecosystem:   npm
  Workspaces:  1
  Resolved:    184 packages (direct 42, transitive 142)
  Lockfile:    package-lock.json (npm, 183 packages)

  Health
  Security         92/100
  Maintenance      76/100
  Supply Chain     88/100
  License          95/100
  Dep. Health     100/100
  Upgrade Risk     97/100
  Overall          90/100 (excellent)

  Findings
  1 Critical · 2 High · 5 Medium · 3 Low  (11 total)

  Top findings
  CRITICAL [Vulnerability] GHSA-…: …
           some-package@1.2.3  DEP-…
           path: (root) > framework-a > utility-b > some-package@1.2.3
```

The exit code tells CI what to do: `0` pass, `1` policy violation, `2` scanner/configuration error.

## CLI

| Command                                 | What it does                                                                           |
| --------------------------------------- | -------------------------------------------------------------------------------------- |
| `deplyze scan`                          | Full analysis: security, health, licenses, outdated, duplicates, unused, supply chain. |
| `deplyze audit` / `analyze` / `analyse` | Aliases for `scan`.                                                                    |
| `deplyze security`                      | Vulnerabilities only.                                                                  |
| `deplyze outdated`                      | Registry version drift, classified patch/minor/major.                                  |
| `deplyze unused`                        | Likely-unused direct dependencies (static evidence only).                              |
| `deplyze duplicates`                    | Packages resolved to more than one version.                                            |
| `deplyze licenses`                      | License distribution and policy violations.                                            |
| `deplyze graph`                         | The resolved dependency graph. `--package lodash` to focus.                            |
| `deplyze package <name>`                | Pre-install intelligence for one registry package.                                     |
| `deplyze guard [install-cmd]`           | Pre-install gate: `ALLOW` / `WARN` / `BLOCK`.                                          |
| `deplyze explain <finding-id>`          | Deep explanation of one finding (`--ai` for an AI-authored one).                       |
| `deplyze upgrade-plan`                  | Ordered upgrade plan (`--ai` to add sequencing advice).                                |
| `deplyze fix` / `remediate`             | Dry run: the commands that _would_ resolve findings.                                   |
| `deplyze ai-review`                     | AI-authored posture review (requires `ai.enabled`).                                    |
| `deplyze sbom`                          | CycloneDX 1.5 or SPDX 2.3 SBOM.                                                        |
| `deplyze policy`                        | Evaluate the configured CI policy.                                                     |
| `deplyze ci`                            | CI mode: analyse, emit SARIF/JSON, set the exit code.                                  |
| `deplyze report`                        | Write a report (`terminal`, `json`, `markdown`, `sarif`, `html`).                      |
| `deplyze mcp`                           | Run the MCP server on stdio.                                                           |
| `deplyze doctor`                        | Environment, configuration and lockfile diagnostics.                                   |
| `deplyze version`                       | Version and build information.                                                         |

Global flags: `--path <dir>`, `--config <file>`, `--offline`, `--no-network`, `--color`,
`--quiet`, `--verbose`, `--debug`.

Common examples:

```bash
deplyze scan --format json
deplyze scan --format sarif
deplyze scan --severity high
deplyze scan --ci
deplyze scan --fail-on critical high
deplyze graph --package lodash
deplyze package lodash
deplyze sbom --format cyclonedx
deplyze guard --package express
deplyze guard npm install some-package
```

## Security analysis

- **Known vulnerabilities** from [OSV](https://osv.dev), queried in batches. CVSS v3.0/v3.1 vectors
  are scored by Deplyze itself using the FIRST specification, so every numeric score is
  reproducible. CVSS v4 vectors are recorded but **not** scored — Deplyze reports the vector and
  marks the numeric score unknown rather than approximating.
- **Vulnerable transitive dependencies**, with the full path from your project:
  `(root) > framework-a > utility-b > vulnerable-package@1.2.3`.
- **Supply-chain signals** — typosquat similarity, brand-new packages, install scripts, unusual
  dependency footprint. These are reported as _signals_, never as verdicts.
- **Lifecycle scripts** (`preinstall`, `install`, `postinstall`, `prepare`, `prepublish`,
  `prepublishOnly`) are read as text and never executed.
- **Deprecated and stale** packages, with the registry's own deprecation message as evidence.

Deplyze distinguishes **confirmed vulnerability**, **potential risk** and **unknown**. A package with
no finding is not declared safe.

## Dependency graph

The graph is built from the lockfile, not just `package.json`. Each node records its ecosystem,
resolved version, dependency kind (prod/dev/optional/peer), depth, license, integrity hash and the
workspace that declared it. The graph powers dependency paths, reverse dependencies (blast radius),
duplicate detection, depth statistics and transitive impact.

```bash
deplyze graph
deplyze graph --package react --direction dependents
```

## License analysis

License expressions (`MIT OR Apache-2.0`, `GPL-2.0 WITH Classpath-exception-2.0`, `LGPL-2.1+`) are
parsed with a small SPDX-aware parser. `OR` succeeds if either branch is acceptable; `AND` requires
both. Unknown licenses are **not** assumed safe — they are reported as unknown.

## SBOM

```bash
deplyze sbom --format cyclonedx --output sbom.cdx.json
deplyze sbom --format spdx --output sbom.spdx.json
deplyze sbom --format cyclonedx --json   # to stdout
```

Includes purls, dependency relationships, hashes (converted from SRI), licenses and advisory
references where available. Serial numbers and timestamps are deterministic for the same project.

## CI/CD

```yaml
# .github/workflows/deplyze.yml
name: Deplyze
on: [push, pull_request]
permissions:
  contents: read
  security-events: write
jobs:
  deplyze:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: deplyze/deplyze/action@v1
        with:
          fail-on: high
          format: sarif
```

Or run the CLI directly:

```bash
deplyze ci --format sarif --output deplyze.sarif
```

Exit codes are part of the public contract:

```text
0 = pass
1 = policy violation
2 = scanner or configuration error
```

## AI features

AI is a layer _on top of_ deterministic analysis, and is disabled by default. When enabled, Deplyze
minimises context: only package names, versions, identifiers, severities and short evidence strings
are sent — **never source code, environment variables or secrets**. Untrusted package metadata is
fenced and the model is explicitly told to treat it as data, not instructions. Every AI output is
labelled as AI-generated, and the deterministic findings remain authoritative.

Supported providers: OpenAI-compatible, Anthropic, Gemini, Ollama (local) and a generic HTTP
provider. Configure with `ai.provider` and `ai.apiKeyEnv` — the API key itself is only ever read
from the environment, never stored in configuration.

## MCP integration

```bash
deplyze mcp
```

Exposes Deplyze to MCP-capable agents (Claude Desktop, Cursor, Codex, and others). Tools include:

```text
deplyze_scan              deplyze_findings          deplyze_security
deplyze_dependency_graph  deplyze_licenses          deplyze_package
deplyze_upgrade_plan      deplyze_remediate         deplyze_sbom
deplyze_policy_check
```

The `deplyze_package` tool is the pre-install workflow: an agent asks "is this package safe to
install?" and receives structured evidence — existence, age, license, deprecation, maintainers,
install scripts, dependency footprint, typosquat similarity — **never a bare `safe: true`**.

See [docs/mcp.md](docs/mcp.md).

## Configuration

`.deplyze.yml` in the project root (or `deplyze.config.{js,mjs,cjs,ts}`, or `--config`):

```yaml
version: 1

scan:
  ecosystems: [npm]
  includeDev: true
  registry:
    enabled: true

security:
  failOn: [critical, high]
  vulnerabilities:
    maxCritical: 0
    maxHigh: 0
  deprecated:
    fail: false

licenses:
  allowed: [MIT, Apache-2.0, BSD-2-Clause, BSD-3-Clause, ISC]
  denied: [AGPL-3.0]
  unknown: warn

packages:
  denied: [suspicious-package]

ignore:
  - id: GHSA-xxxx-yyyy-zzzz
    reason: 'Accepted temporarily while the upstream migration is prepared'
    expires: '2027-01-01'
```

See [docs/configuration.md](docs/configuration.md) for every option.

## Architecture

```text
                    ┌──────────────────┐
                    │   Deplyze Core   │  model, graph, findings, risk primitives
                    └────────┬─────────┘
        ┌────────────────────┼────────────────────┐
   Ecosystem             Intelligence            Policy
   Adapters               Engines                 Engine
   npm / pnpm            vulnerability            rules
   yarn / bun            health / graph           suppressions
                         license / sbom / risk    thresholds
        │                    │
        └────────────────────┼────────────────────┐
                    ┌────────▼─────────┐
                    │ Output Adapters  │
                    │ CLI · JSON · MD  │
                    │ SARIF · HTML     │
                    │ MCP · (API later)│
                    └──────────────────┘
```

The core engine has no dependency on the CLI, the reporters, the AI layer or MCP. See
[docs/architecture.md](docs/architecture.md).

## Security model

Deplyze treats dependency metadata as hostile input. It never executes lifecycle scripts, never
runs a package manager, and never evaluates code from a lockfile. It defends against path traversal,
command injection, SSRF (package names are validated before use in URLs), prototype pollution,
ReDoS (bounded regexes and size limits), oversized responses and prompt injection. See
[docs/security-model.md](docs/security-model.md) and [SECURITY.md](SECURITY.md).

## Privacy

Local scanning is the default. Deplyze does **not** upload your source code. The only external
requests are:

| Destination          | When                                                | Data sent                                  |
| -------------------- | --------------------------------------------------- | ------------------------------------------ |
| `api.osv.dev`        | Advisory lookup (unless `--offline`/`--no-network`) | package name + version                     |
| `registry.npmjs.org` | Metadata for direct/unknown-license packages        | package name                               |
| `api.npmjs.org`      | `deplyze package --check-downloads`                 | package name                               |
| Your AI provider     | Only if you enable AI and pass `--ai`               | minimised finding context (no source code) |

`--offline` forbids all network access and uses only cached data. `--no-network` disables registry
and advisory access entirely.

## Repository layout

```text
apps/cli            the `deplyze` CLI
packages/core       domain model, graph, findings, risk primitives, semver, safety helpers
packages/ecosystems manifest + lockfile parsers and project detection
packages/advisories OSV client, normalization, CVSS scoring, caching, matching
packages/config     configuration schema, loading and resolution
packages/risk       explainable scoring engine
packages/scanners   vulnerability, license, duplicate, outdated, health, lifecycle, unused, supply-chain
packages/sbom       CycloneDX and SPDX generation
packages/reporters  terminal, JSON, Markdown, SARIF and HTML reporters
packages/policies   suppressions and CI policy evaluation
packages/ai         provider abstraction and context minimisation
packages/mcp        MCP server and tools
fixtures            deliberately vulnerable / malformed / monorepo test projects
docs                architecture, configuration, rules, security model, MCP, AI
```

## Roadmap

Implemented and tested today: JavaScript/TypeScript ecosystems (npm, pnpm, Yarn v1 + Berry, Bun
lockfiles), OSV advisories, the full scanner set, risk scoring, policies, suppressions, SBOM, all
report formats, MCP, and optional AI.

Not implemented yet, and explicitly **not** claimed:

- Python/PyPI, Rust/Cargo, Go, Maven, NuGet, Composer and Bundler adapters (the interfaces exist;
  the adapters do not). `SUPPORTED_ECOSYSTEMS` in `@deplyze/core` is the source of truth.
- A hosted dashboard or REST API. The architecture leaves room for both; neither ships today.
- Automatic remediation. `deplyze fix` prints commands; it never runs them.
- OSV is the only live advisory source wired up. GitHub Advisory and NVD normalization paths are
  future work; OSV aggregates both.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Bug reports, adversarial fixtures and new ecosystem
adapters are especially welcome.

## License

Apache-2.0. See [LICENSE](LICENSE).
