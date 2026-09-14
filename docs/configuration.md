# Configuration

Deplyze looks for configuration in the project root, in this order:

1. `--config <file>`
2. `.deplyze.yml`
3. `.deplyze.yaml`
4. `.deplyze.json`
5. `deplyze.config.js`
6. `deplyze.config.mjs`
7. `deplyze.config.cjs`
8. `deplyze.config.ts`

Executable config files are imported, which runs their code. That is a deliberate, documented
opt-in. Nothing else in Deplyze ever executes project code.

Unknown top-level keys produce a warning rather than being silently ignored, so a typo such as
`secuirty:` cannot quietly disable a policy.

## Reference

```yaml
version: 1

scan:
  ecosystems: [npm] # ecosystems to analyse
  include: [] # globs to include
  exclude: [] # globs to exclude
  includeDev: true # analyse devDependencies
  maxFileBytes: 67108864 # per-file read limit (64 MiB)
  maxNodes: 250000 # hard cap on graph nodes
  concurrency: 8 # bounded parallelism
  offline: false # never use the network
  cache:
    directory: .deplyze-cache # where advisories/registry data are cached
    ttlHours: 6
  registry:
    enabled: true
    url: https://registry.npmjs.org
    concurrency: 8
    maxPackages: 2000 # cap on registry lookups per scan
    timeoutMs: 15000

advisories:
  enabled: true
  sources: [osv] # OSV is the supported live source
  ttlHours: 6
  timeoutMs: 20000
  allowNetwork: true

security:
  failOn: [critical, high] # severity threshold for CI
  vulnerabilities:
    maxCritical: 0 # optional ceilings (omit for no limit)
    maxHigh: 0
    # maxMedium: 0             # add ceilings only if you want them
    allowedAdvisories: [] # advisory ids to ignore
  deprecated:
    fail: false
  installScripts:
    failOn: [] # e.g. [high] to fail on suspicious scripts
    allow: [] # package names whose scripts are acceptable

licenses:
  allowed: [] # empty = no allowlist restriction
  denied: [AGPL-3.0]
  unknown: warn # ignore | warn | fail
  failOnDenied: true

packages:
  allowed: [] # never report these
  denied: [] # always a policy violation
  unusedAllow: [] # skip these in unused-dependency analysis

supplyChain:
  typosquat:
    enabled: true
    maxDistance: 2
    minNameLength: 5
  newPackageDays: 30
  maxDependencyFootprint: 250
  allowlist: []

unused:
  enabled: true
  entrypoints: []
  ignore: [] # additional false-positive controls

outdated:
  enabled: true
  failOnMajor: false
  failOnMinor: false

output:
  format: terminal # terminal | json | markdown | sarif | html
  color: auto # auto | always | never
  quiet: false
  verbose: false
  # reportFile: deplyze-report.md

ai:
  enabled: false # AI is opt-in, always
  provider: none # none | openai | anthropic | gemini | ollama | http
  model: ''
  baseUrl: ''
  apiKeyEnv: '' # NAME of the env var holding the key, never the key
  maxTokens: 1500
  temperature: 0.2
  timeoutMs: 60000
  redact: true
  maxFindings: 25

ci:
  format: terminal # terminal | json | markdown | sarif
  sarifFile: ''
  failOn: [] # overrides security.failOn in CI mode
  annotations: true

ignore:
  - id: GHSA-xxxx-yyyy-zzzz # finding id or advisory id
    reason: 'Why this is acceptable' # required
    expires: '2027-01-01' # optional; expired suppressions never suppress
    package: some-package # optional; scope the suppression to one package
    createdBy: '@someone'
```

## Suppressions

A suppression must have a `reason`. When it expires (or its date is malformed) it stops suppressing
and is reported as expired. Suppressions that match nothing are reported as unused so stale entries
can be cleaned up. Suppression is never silent.

## Example

```yaml
version: 1

security:
  failOn: [critical, high]
  vulnerabilities:
    maxCritical: 0

licenses:
  allowed: [MIT, Apache-2.0, BSD-2-Clause, BSD-3-Clause, ISC]
  denied: [AGPL-3.0]
  unknown: fail

packages:
  denied: [event-stream]

ignore:
  - id: GHSA-p6mc-m468-83gw
    reason: 'Pinned wait for the maintenance release; tracked in JIRA-1234'
    expires: '2026-12-31'
```
