# Fixtures

Deliberately small projects used by the test suite. They are **not** real applications and must
never be installed or published. Their lockfiles are hand-written and include synthetic packages
(`nested-transitive`, `@fixture/lib`) so tests do not depend on the live registry.

| Fixture | Purpose |
| --- | --- |
| `vulnerable-project` | A vulnerable direct dependency (`lodash@4.17.15`) plus a transitive package. |
| `duplicate-project` | The same package resolved to two versions. |
| `unused-project` | A declared dependency with a matching source tree (used for unused analysis). |
| `license-project` | Denied, dual-licensed and unknown licenses. |
| `gpl-project` | A copyleft license used for policy tests. |
| `typosquat-project` | A package name that resembles a popular package. |
| `lifecycle-script-project` | Install scripts, including a suspicious command, inspected but never executed. |
| `malformed-lockfile` | Truncated `package-lock.json` used to test safe failure. |
| `monorepo` | A pnpm workspace with `@fixture/lib` and `@fixture/api` packages. |

Do not add real credentials, real vulnerable tarballs, or anything that executes on install.
