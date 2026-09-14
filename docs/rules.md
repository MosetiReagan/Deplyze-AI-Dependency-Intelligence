# Finding rules

Every Deplyze finding has a `source` (the detector), a `category`, a `severity`, a `confidence`, the
`evidence` that produced it, and usually a `remediation`. Ids are deterministic: `DEP-<hash>` derived
from the issue identity, so a suppression keeps working across lockfile churn.

Confidence is one of `high`, `medium`, `low`, `unknown`. Evidence kinds are stable strings
(`affected-range`, `dependency-path`, `not-executed`, `similarity`, …) so they can be consumed
programmatically.

## `security/vulnerability`

- **Category:** vulnerability · **Confidence:** high
- Matches resolved versions against OSV advisories using explicit version lists and semver ranges.
  Reports the advisory id, aliases, installed version, the matched range, the fixing version, CVSS
  score/vector (v3 only), and the dependency path from your project.
- **Fix:** upgrade to the reported fixed version; major upgrades are flagged as breaking.

## `license/policy` and `license/unknown`

- **Category:** license
- `license/policy` (severity `high`) fires when a license is denied or is outside the allowlist.
  `license/unknown` (severity `low`, or `high` when `unknown: fail`) fires when no license can be
  determined. Deplyze never treats an unknown license as permissive.

## `graph/duplicates`

- **Category:** duplicate · **Severity:** `medium` across majors, `low` within a major
- Reports packages resolved to more than one version, with the versions, their dependents and
  dependency paths.

## `outdated/versions`

- **Category:** outdated · **Severity:** `medium` (major), `low` (minor), `info` (patch)
- Compares installed versions with the registry, and reports release ages. Direct dependencies are
  reported for every lag kind; transitive dependencies are reported for majors only, where the fix
  usually requires updating a direct dependency.

## `maintenance/deprecated` and `maintenance/stale`

- **Category:** maintenance
- `maintenance/deprecated` (severity `medium` direct, `low` transitive) quotes the registry's
  deprecation notice. `maintenance/stale` (severity `low`, confidence `medium`) reports direct
  dependencies with no release in 24 months and explicitly states that a slow cadence is not by
  itself a security problem.

## `supply-chain/lifecycle-scripts`

- **Category:** supply-chain · **Severity:** `high`/`medium` when a script matches a suspicious
  pattern, `low`/`info` for an ordinary install hook
- Reports the script name and command text. It always includes a `not-executed` evidence entry:
  Deplyze inspects scripts as text and never runs them.

## `supply-chain/typosquat`

- **Category:** supply-chain · **Confidence:** `high`/`medium`/`low`
- Damerau-Levenshtein similarity against a curated list of popular packages. Reports the similarity
  score, edit distance, target and a confidence level. It is deliberately conservative and never
  asserts malicious intent.

## `supply-chain/new-package`

- **Category:** supply-chain · **Severity:** `medium`
- A direct dependency first published within the configured window. Age is reported as a signal, not
  a verdict.

## `unused/dependencies`

- **Category:** unused · **Severity:** `low` (or `info` for dev dependencies)
- Static analysis of imports, `require()`, package scripts, config files and package `bin` names.
  Confidence drops to `low` when dynamic imports or unread files are present. Deplyze never removes a
  dependency; the finding says so explicitly.

## Risk scoring

Six categories start at 100 and lose points through capped, additive rules: `security` (35%
weight), `supply-chain` (20%), `maintenance` (15%), `license` (15%), `dependency-health` (10%) and
`upgrade-risk` (5%). The overall score is the weighted mean. Higher is healthier. Every deduction is
reported as a `ScoreContribution` with a human-readable reason and the finding ids that justify it.

Deplyze does not pretend to a precision the evidence does not support: a project with no findings
scores 100, and a single critical vulnerability cannot mathematically mask the rest of the report.
