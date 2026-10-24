# Release review — 2026-10-24

The published `0.1.0-alpha.1` release fixes a custom-policy race, checks deadlines when results settle, bounds JSON normalization, strengthens the conformance assertions, and adds MCP SDK and packaged-consumer tests. These fixes are not in the earlier `0.1.0-alpha.0` packages.

This review covers the documented single-process API and its package distribution. It is not an independent security audit. Branch protection and repository security settings are enabled. Hosted checks passed on the release commit, and registry installation, integrity and source metadata were verified after publication.

## Findings and fixes

### Deadline and JSON resource limits

A synchronous handler could return after its deadline before the cancellation timer got a turn on the event loop. Settlement now checks the clock and rejects the result with `EXECUTION_ABORTED`, preserving its charge and releasing concurrency only after the handler settles. Regression cases cover synchronous and immediately resolved results.

The 1 MiB JSON limit previously ran after cloning and serializing the entire value. Repeated references to a large string could cause excessive allocation before rejection. Normalization now counts canonical UTF-8 bytes as it traverses, including string escapes, keys and punctuation. Tests cover exact boundaries, early rejection of repeated values and oversized handler results that retain their full charge and revoke the task.

### Stale state during custom policy evaluation

Two concurrent calls could both observe `calls === 0` and pass a custom policy that allowed only the first call. Built-in budgets still held, but the custom restriction could be violated.

Preparation and dispatch now compare the supplied task snapshot with current state after policy evaluation. Changed counters or sensitivity cause `POLICY_STATE_CHANGED` before a handler starts, an approval is consumed, or budget is reserved. The host may retry with a fresh policy evaluation. Policies that read mutable external state still need host-side coordination.

### Conformance cases that could miss faulty behavior

S08 captured its effect baseline after execution began, so premature handler execution could go unnoticed. The baseline now precedes dispatch, and a deliberately faulty implementation fails the test.

S10 now checks nonzero charges when a handler omits usage or fails. It also detects retained concurrency reservations. Catalog version `1.1.0` identifies these stronger assertions.

Each variant now has a configurable asynchronous timeout. A timeout reports a failed case and lets the suite continue; it cannot stop blocking JavaScript or cancel unfinished adapter work.

### MCP and package coverage

The official SDK tests exercise `tools/list` and `tools/call`, metadata changes, denials, approvals, cancellation, failures and cost settlement. Packed packages are installed into a clean consumer, where their public types and README TypeScript examples compile. A typed MCP consumer then runs denied and allowed calls.

Cancellation tests also confirm an integration limit: an SDK request can reject before its remote handler stops. The guard tracks the bridge promise. Enforce remote concurrency, cancellation and cost limits at the server or provider.

### Release artifacts

Publication preflight now requires a clean Git checkout, aligned workspace versions and exact internal dependency versions before and after checks. Builds remove old output before compiling, and `npm pack` rebuilds the packages. The package check plants an obsolete file in each workspace and verifies that it cannot enter the tarball.

These changes prevent stale output and uncommitted source from entering subsequent releases. They do not change the source metadata recorded for the initial release.

## Repository and workflow hardening

The [release branch ruleset](https://github.com/ShieldaAI/agent-guard/rules/25781227) protects `main` and release branches. The sole-maintainer policy requires a pull request, resolved review conversations and successful, up-to-date Node 22/24/26 checks from GitHub Actions. It does not require a second person's approval. There is no bypass list. Version tags matching `v*` cannot be changed or deleted, and only administrators may create them.

Secret scanning, push protection, Dependabot security updates and private vulnerability reporting are enabled. Repository settings require full commit hashes for actions and approval before workflows from external forks run.

The committed workflows disable persisted checkout credentials, bound job runtimes and retain CI tarballs for seven days. CodeQL analyzes TypeScript and GitHub Actions, and dependency review checks newly introduced advisories rated moderate or higher. Dependabot configuration covers npm packages and GitHub Actions. Hosted results for the release are recorded below.

## Validation

- The current `npm run check` passed on Node 22.23.4, 24.22.1 and 26.12.0: all three packages built, 121 tests passed, and installed tarballs passed the consumer check. Deadline and bounded-normalization regressions pass, and the packing regression confirms that obsolete build output is excluded.
- The earlier runtime review passed the same 114 tests on Node 22.0.0, 22.23.4, 24.22.1 and 26.12.0 on macOS.
- [Hosted CI run 40132729269](https://github.com/ShieldaAI/agent-guard/actions/runs/40132729269) passed on 2026-10-24 for release commit `86cf5902acbbc029b0872060c1906cc25964ec5d`. All three Node 22/24/26 jobs passed installation and `npm run check`; Node 24 also packed and uploaded the tarballs.
- [CodeQL run 40132729355](https://github.com/ShieldaAI/agent-guard/actions/runs/40132729355) passed on the release commit. [Dependency-review run 40132541222](https://github.com/ShieldaAI/agent-guard/actions/runs/40132541222) passed on final pull-request head `9e74bf9fd4fdb06a0f4b9e527f8cce240ace33a7` before the merge.
- All 20 malicious/benign scenario variants pass. Regressions using deliberately faulty implementations fail the intended variants.
- The MCP suite includes 18 tests covering the adapter and official SDK integration.
- The current Node 26 coverage run reported 99.78% lines and 93.61% branches across built package JavaScript. Core and MCP each reached 100% line coverage. Coverage measures exercised code, not resistance to all attacks.
- Nine preflight tests cover clean and dirty checkouts, version mismatches, internal dependency ranges and invalid publication locations.
- Core still has no third-party runtime dependencies. MCP SDK packages are pinned development dependencies.
- `npm audit` reported no known vulnerabilities in the installed dependency tree on 2026-10-24.
- Actionlint 1.7.12 validated all three workflows. Action hashes were checked against the corresponding upstream release tags, checkout credentials are not persisted, and default token permissions are read-only. This is local configuration validation, not a hosted scan result.

## Publication record and remaining work

All three `0.1.0-alpha.1` packages are available on npm. Their `gitHead` values match release commit `86cf5902acbbc029b0872060c1906cc25964ec5d`, and downloaded registry tarballs match the inspected local artifacts byte for byte. A fresh public-registry installation passed declaration and README compilation, MCP dispatch and all 20 conformance variants. Each publication ran the full 121-test prepublish check.

The protected `v0.1.0-alpha.1` tag points to that commit. The [GitHub prerelease](https://github.com/ShieldaAI/agent-guard/releases/tag/v0.1.0-alpha.1) includes all three tarballs and verified SHA-256 checksums. The `alpha` dist-tag points to `0.1.0-alpha.1`; `latest` remains on `0.1.0-alpha.0`. Later documentation updates do not change the release tag or published artifacts.

Build provenance remains future work, preferably through a restricted trusted-publishing workflow. Registry signatures and matching hashes establish artifact integrity but do not attest to the build process. The version tag is protected against changes and deletion; GitHub release assets do not have release immutability enabled.

The initial packages record `gitHead` `6db7631a1f9ba070b5e5c9b2a5152be0584b0622`, but their packaged READMEs match release tag commit `f7e4c77d675a6ec2fd7ab402858d49038ccc86ea`. Executable files and integrity hashes were verified; the discrepancy affects documentation traceability. See [the release instructions](releasing.md).

For production privilege enforcement, test the host integration, credential isolation and resource-side controls, and obtain a security review appropriate to the application's risk. This alpha keeps authorization state in memory and does not provide distributed enforcement.
