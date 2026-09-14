# Security Policy

Deplyze is security-sensitive software: it parses untrusted files and metadata from the ecosystem it
audits. We take reports about Deplyze itself as seriously as the vulnerabilities it finds.

## Reporting a vulnerability

**Please do not open a public issue for a security vulnerability.**

Report privately using GitHub's [private vulnerability reporting](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability)
on the `deplyze/deplyze` repository, or email the maintainers listed in `package.json`.

Please include:

- A description of the issue and its impact.
- Steps to reproduce, ideally a minimal fixture.
- Affected versions and configuration.

We aim to acknowledge reports within 72 hours and to publish a fix and advisory once a fix is
available. We will credit reporters unless they ask to remain anonymous.

## Scope

In scope:

- Path traversal or arbitrary file read/write via manifests, lockfiles, configuration or report paths.
- Command injection or arbitrary code execution.
- SSRF via package names, registry URLs or advisory URLs.
- Resource exhaustion (ReDoS, unbounded memory/CPU, oversized inputs).
- Prototype pollution in parsers.
- Leakage of secrets (API keys, tokens) in logs, reports or AI prompts.
- Weaknesses in the AI context minimisation or prompt-injection fencing.

Out of scope:

- Findings about _your_ dependencies. Deplyze reports those; it does not own them.
- Vulnerabilities in advisory data itself (report those to OSV/GitHub).
- Anything requiring an attacker to already control the developer's machine or the AI provider.

## Security design

Deplyze's guarantees are documented in [docs/security-model.md](docs/security-model.md). In short:

- It never executes package code or lifecycle scripts.
- It never installs, upgrades or edits anything.
- Package names used in URLs are validated first, preventing SSRF.
- Report/output paths must stay inside the project root.
- Inputs are size-limited and regexes are bounded.
- AI is opt-in, sends no source code, and is fed fenced, redacted context.

## Supported versions

Deplyze is pre-1.0. Security fixes are released for the latest minor version.
