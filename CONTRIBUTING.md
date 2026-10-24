# Contributing

Use Node.js 22 or newer and npm. Run `npm ci --ignore-scripts`, make a focused change,
then run `npm run check`. This builds all packages, tests authorization and accounting
behavior, and installs tarballs into a clean consumer. The consumer compiles the public
declarations and README TypeScript examples, executes an MCP call through the packed
adapter, and runs the conformance fixtures.

Release preflight tests use temporary Git repositories to cover dirty checkouts and inconsistent package versions. Local checks and packing support uncommitted work; publication requires a clean committed source checkout. See [the release process](docs/releasing.md).

For a new protection, add an unsafe request that cannot reach its handler and a benign request that completes. Cover concurrent calls, revoked or changed permissions, and failures where relevant. A returned denial alone is not sufficient evidence if a handler has already run.

Keep the core's runtime dependency set empty unless a dependency materially improves correctness. Keep grant checks, approvals and budget admission in the core. MCP and other adapters must call that implementation.

Do not put real secrets, private organization data or live destructive targets in fixtures. Use synthetic identifiers and in-memory effect logs. Discuss behavior changes and document their scope in `docs/scenarios.md` and `docs/threat-model.md`.

Contributions are provided under this repository's Apache-2.0 license. Security findings should use the private process in SECURITY.md rather than a public issue.
