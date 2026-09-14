# Security model

Deplyze is a security tool that consumes hostile input: manifests, lockfiles and registry metadata
are all attacker-influenceable. This document describes the guarantees Deplyze makes and how they
are enforced.

## Guarantees

1. **No code execution.** Deplyze never runs `npm install`, never executes lifecycle scripts, never
   evaluates lockfile or manifest content as code, and never shells out based on package metadata.
2. **Read-only.** Deplyze never modifies your manifests, lockfiles or lockfile-managed files. The
   only files it writes are caches, reports and SBOMs, and only where you ask.
3. **No source upload.** Local scanning is the default. Source code is never transmitted.
4. **Opt-in AI.** AI features are disabled unless you enable them, and even then only minimised,
   redacted, fenced context is sent.

## Threats and mitigations

### Path traversal

- Report/SBOM output paths are resolved and validated against the project root; writes outside it are
  refused (`resolveWithin`, `assertWritablePath`).
- Cache keys are hashed before touching the filesystem (`DiskCache`), so a key containing `../` or a
  NUL byte cannot influence the path.
- Source scanning refuses symlink escapes and caps directory traversal.

### Command injection

Deplyze builds no shell command from metadata. The commands shown by `deplyze fix` and in findings
are display strings; nothing executes them. Package names are quoted/encoded before appearing in any
suggested command or URL.

### SSRF

Package names are validated (`assertSafePackageName`) before being interpolated into a registry URL.
Names containing `/`, whitespace, `..`, control characters or URL syntax are rejected. Advisory ids
are URL-encoded. Registry base URLs must parse as `http:`/`https:`.

### Prototype pollution

Parsers read `JSON.parse` output into maps and arrays; object keys that are not expected are
preserved but never assigned onto prototypes. `__proto__`/`constructor` keys cannot take over the
process, and Zod validates structural fields.

### ReDoS and resource exhaustion

- Regexes are bounded; user content length is capped (`maxFileBytes`).
- Graph traversal is bounded (`maxNodes`), network concurrency is bounded, and responses are
  size-limited before parsing.
- Source scanning caps file count, per-file size and total bytes, and reports truncation instead of
  silently continuing.

### Oversized or malformed archives/files

Deplyze does not extract archives. Lockfiles larger than the configured limit are rejected rather
than partially parsed and trusted.

### Prompt injection

Package metadata (advisory summaries, deprecation notices, lifecycle scripts) is attacker controlled.
Before reaching a model it is wrapped in `<<<UNTRUSTED-DATA ... UNTRUSTED-DATA>>>` fences, the model
is instructed to treat it as data and never as instructions, embedded fence markers are filtered out,
and secrets are redacted.

### Secret leakage

- API keys are read from environment variables only; configuration stores the _name_ of the variable.
- `redactSecrets` scrubs tokens from prompts, logs and provider error details.
- Structured logs never include secrets, credentials or request bodies.
- Provider errors include only a redacted, truncated detail string.

## External network calls

| Destination            | Purpose                 | Trigger                                                                            | Payload                                   |
| ---------------------- | ----------------------- | ---------------------------------------------------------------------------------- | ----------------------------------------- |
| `api.osv.dev`          | Advisory lookup         | default (disable with `--offline`/`--no-network`/`advisories.allowNetwork: false`) | package name + version                    |
| `registry.npmjs.org`   | Package metadata        | direct dependencies, unknown-license packages                                      | encoded package name                      |
| `api.npmjs.org`        | Weekly downloads        | `deplyze package --check-downloads`                                                | encoded package name                      |
| configured AI endpoint | Explanation/remediation | `--ai` with `ai.enabled: true`                                                     | minimised finding context, no source code |

`--offline` makes Deplyze use only cached data and never open a network connection. `--no-network`
additionally disables registry metadata entirely.

## AI safety

- Context minimisation sends package names, versions, ids, severities and short evidence strings.
- No source code, environment variables, file contents or full dependency trees are sent.
- AI output is always labelled as AI-generated; deterministic findings remain authoritative.
- AI cannot cause Deplyze to execute anything.
