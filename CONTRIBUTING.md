# Contributing

Thank you for helping. Small, focused changes are the easiest to review.

## Set up and check your change

You need Node.js 22.13 or newer and npm, and on Linux or macOS the system C compiler
(`/usr/bin/cc`; on macOS, the Xcode Command Line Tools). No Docker, database or API key.

```sh
npm ci --ignore-scripts
npm run check
```

`npm run check` takes several minutes. It builds every package, runs all the JavaScript
tests, and installs the packed packages into a clean project to compile the public types
and the TypeScript examples in the READMEs.

To work on one thing at a time:

```sh
npm run build                                   # needed once, and after changing a package's source
node --test packages/core/test/budgets.test.mjs # one test file
npm run format                                  # before committing
```

CI runs `npm run format:check` and fails on unformatted TypeScript, JavaScript, JSX or the
viewer's CSS. Markdown and JSON files are not reformatted.

Some tests are skipped unless their tools are present, and CI runs them for you: the Docker
sandbox tests, the Neo4j integration tests of the Python collector (see its
[README](integrations/cartography/README.md)), and the browser checks. The C compiler is
used by one recovery test, which builds a small test-only helper; published packages do
not need a compiler.

## What a change should include

- **A new protection** needs two tests: an unsafe request that never reaches its handler,
  and an ordinary request that completes. Cover concurrent calls, revoked or changed
  permissions, and failures where they apply. Check that the handler did not run; a
  returned denial does not show that.
- **Behavior changes** are described in the changelog, and in `docs/scenarios.md` and
  `docs/threat-model.md` when they change what is covered. Open an issue first if you are
  unsure whether a change is wanted.
- **Keep the core small.** The core has no runtime dependencies; add one only if it
  materially improves correctness. Grant checks, approvals and budget admission live in
  the core, and the MCP adapter and other adapters call that implementation.
- **No real data in fixtures.** Use synthetic identifiers and in-memory effect logs: no real
  secrets, private organization data or live destructive targets.

## Reporting a vulnerability

Do not open a public issue. Use the private process in [SECURITY.md](SECURITY.md).

## Releases

Maintainers follow [the release process](docs/releasing.md). Local checks and packing work
on uncommitted changes; publishing requires a clean, committed checkout.

## Licence and conduct

Contributions are provided under this repository's Apache-2.0 licence. Everyone taking
part is expected to follow the [code of conduct](CODE_OF_CONDUCT.md).
