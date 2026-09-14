# MCP server

Deplyze ships a [Model Context Protocol](https://modelcontextprotocol.io) server so AI coding agents
can ask dependency questions and receive structured, evidence-backed answers. This is the layer
between an agent and the repository: when an agent wants to add a package, Deplyze tells it whether
that package exists, how old it is, what it depends on, whether it installs anything, what its
license is and whether its name resembles a popular package.

## Running

```bash
deplyze mcp            # stdio transport
deplyze mcp --path /path/to/project   # default project directory
```

## Client configuration

### Claude Desktop / Cursor / Codex (stdio)

```json
{
  "mcpServers": {
    "deplyze": {
      "command": "npx",
      "args": ["-y", "deplyze", "mcp"]
    }
  }
}
```

## Tools

| Tool                       | Purpose                                                                                                          |
| -------------------------- | ---------------------------------------------------------------------------------------------------------------- |
| `deplyze_scan`             | Full scan summary and findings, filtered by severity/category/limit.                                             |
| `deplyze_findings`         | Findings list (same shape as `deplyze_scan`).                                                                    |
| `deplyze_security`         | Vulnerability findings plus the advisory ids that were retrieved and any that were unresolved.                   |
| `deplyze_dependency_graph` | Graph statistics and duplicates, or a focused query for one package (versions, paths, dependents, dependencies). |
| `deplyze_licenses`         | License distribution and policy violations, with a disclaimer that Deplyze is not legal advice.                  |
| `deplyze_package`          | Pre-install intelligence for a registry package.                                                                 |
| `deplyze_upgrade_plan`     | Ordered upgrades derived from security fixes and version drift, with breaking-change flags.                      |
| `deplyze_remediate`        | Ordered remediation steps; never applied.                                                                        |
| `deplyze_sbom`             | SBOM summary plus the CLI invocation for the full document.                                                      |
| `deplyze_policy_check`     | The policy result and the exit code CI would produce.                                                            |

## Why there is no `safe: true`

An agent asking "is this package safe?" gets evidence, not a boolean. `deplyze_package` returns
existence, first-published age, license, deprecation notice, maintainer count, weekly downloads
(optional), lifecycle scripts, direct dependency count and list, repository, and any typosquat
signal — together with an explicit statement that Deplyze does not return a boolean verdict.

The reasoning is simple: a package can be safe on every axis Deplyze checks and still be malicious in
a way no metadata reveals. A boolean would be a false guarantee. The `deplyze_scan` tool says the
same thing about a clean scan: "a package with no finding is not guaranteed safe."

## Example agent workflow

```text
agent:          "I want to install `expreess`."
deplyze_package →  exists: true
                   typosquat: { similarTo: "express", distance: 1, confidence: "medium" }
                   ageDays: 3
                   weeklyDownloads: 41
                   lifecycleScripts: { postinstall: "node setup.js" }
agent:          escalates to the developer instead of installing.
```

## Caching

The server memoises scans per resolved project path for the lifetime of the process, so several tool
calls in a row do not re-scan. Paths are resolved through `realpath` so a symlink cannot alias two
projects.
