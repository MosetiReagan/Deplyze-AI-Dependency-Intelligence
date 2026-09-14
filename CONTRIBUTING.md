# Contributing to Deplyze

Thanks for helping. Deplyze is a security tool, so correctness and evidence matter more than
features. A small, well-tested change is worth far more than a large, clever one.

## Prerequisites

- Node.js 20 or newer
- pnpm 10 (`corepack enable` is the easiest way to get it)

## Getting started

```bash
git clone https://github.com/deplyze/deplyze.git
cd deplyze
pnpm install
pnpm build
pnpm test
```

## Everyday commands

```bash
pnpm lint          # ESLint
pnpm typecheck     # tsc --noEmit for every workspace
pnpm test          # unit tests (hermetic; no network)
pnpm test:integration  # opt-in; hits the real OSV/npm APIs
pnpm build         # build every package and the CLI
pnpm format        # Prettier
```

Run the CLI from source without building:

```bash
pnpm deplyze scan --path fixtures/vulnerable-project
```

## Repository conventions

- **ESM only.** All packages are `"type": "module"`; imports use `.js` extensions.
- **Strict TypeScript.** `strict` and `noUncheckedIndexedAccess` are on. Prefer narrowing over
  non-null assertions in `src/`.
- **No new runtime dependencies without justification.** Every dependency added to Deplyze itself
  must be explained in the pull request. Prefer the standard library.
- **Deterministic output.** Findings, ids and scores must not depend on iteration order, wall-clock
  time (unless injected) or network timing.
- **Evidence or silence.** If a detector cannot verify something, report `unknown`. Never invent a
  vulnerability, version, license or score.

## Adding a scanner

1. Create `packages/scanners/src/<your-scanner>.ts` exporting a `Scanner`.
2. Register it in `defaultScanners()` in `packages/scanners/src/orchestrate.ts`.
3. Emit findings with `createFinding()`, using a `stableId` so suppressions survive lockfile churn.
4. Attach `evidence` entries that explain _what_ was found and _why it matters_.
5. Add a test under `packages/scanners/test/` that constructs a `ScanContext` with `makeContext()`
   from `test/helpers.ts`. Never hit the network in a unit test.

## Adding an ecosystem adapter

Implement the `LockfileParser` interface in `packages/ecosystems/src/model.ts`, register it in
`packages/ecosystems/src/loader.ts`, and add it to `SUPPORTED_ECOSYSTEMS` in `packages/core/src/types.ts`
**only once a real project resolves correctly through it.** Do not list an ecosystem as supported
before it works end to end.

## Tests

- Unit tests are hermetic: no network, deterministic fixtures, injected fetch where needed.
- Integration tests (`*.integration.test.ts`) may use real APIs and run only under
  `pnpm test:integration`.
- New detectors need at minimum: a positive case, a negative case, and a "malformed input" case.
- Adversarial fixtures live in `fixtures/` (for example `malformed-lockfile`, `lifecycle-script-project`).

## Pull requests

- Keep the change focused; unrelated refactors belong in a separate PR.
- Update documentation and `CHANGELOG.md` for user-visible changes.
- Make sure `pnpm lint && pnpm typecheck && pnpm test && pnpm build` all pass.

## Commit messages

Conventional-commit style is appreciated (`feat:`, `fix:`, `docs:`, `test:`, `refactor:`) but not
enforced. Explain _why_ in the body.

## Reporting bugs and security issues

- Functional bugs: open a GitHub issue using the bug template.
- Security issues: **do not** open a public issue. See [SECURITY.md](SECURITY.md).

## Code of conduct

Participation is covered by [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
