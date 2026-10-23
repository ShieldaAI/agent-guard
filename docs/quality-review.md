# Quality review — 2026-10-24

The published `0.1.0-alpha.0` release does not meet a 9/10 assessment. Review found a reproducible custom-policy race and false-positive conformance results. The candidate fixes those findings and adds integration and distribution evidence, but the overall project remains approximately **8.5/10** until release controls and a new verified publication are complete.

These are engineering judgments for the documented experimental-alpha scope, not measured attack-prevention rates, certification or an independent external security audit. A 9/10 alpha implementation should have no unresolved reproduced correctness issue within its stated boundary, regressions that observe actual effects, representative integration tests, usable packaged types and examples, and explicit limitations. A 9/10 release also needs verifiable correspondence between reviewed source, successful CI, tag and published artifacts.

| Area | Candidate assessment | Basis and scope |
|---|---|---|
| `@shieldaai/agent-guard` | 9/10 for its in-process alpha boundary | Snapshot freshness closes the reproduced policy race; effect-counting regressions and existing authority, approval, JSON and budget tests pass. This does not cover hostile code, durable state or distributed admission. |
| `@shieldaai/agent-guard-mcp` | 9/10 as a thin `tools/call` bridge | Official SDK v2.4.0 integration covers real protocol calls, approval, metadata changes, errors, cancellation and cost settlement. HTTP/stdio, server authentication and other MCP methods remain outside the tested scope. |
| `@shieldaai/agent-guard-scenarios` | 9/10 as a synthetic conformance suite | Malicious/benign pairs and deliberately faulty implementations test the assertions themselves. Ten scenarios are not a comprehensive prompt-injection benchmark. |
| Release assurance | About 8.5/10; blocks overall 9/10 | Local package checks improved; hosted CI, protected release source and exact publication traceability are still pending. |

## Findings and corrections

1. **High: a custom policy could admit concurrent calls using stale task counters.** Two executions could both observe `calls === 0` and pass a policy allowing only the first call. Mandatory built-in budgets remained enforced, but a tighter custom restriction could be violated. Preparation and dispatch now compare every mutable field in the supplied snapshot after policy evaluation. A change rejects with `POLICY_STATE_CHANGED` before any handler, approval consumption or reservation. The host can retry through a fresh policy evaluation. External mutable state consulted by a policy still needs host coordination.
2. **High for conformance reliability: S08 could pass after premature handler execution.** Its effect baseline was captured after execution began. The baseline now precedes dispatch and the test checks the effect ledger explicitly. A deliberately faulty implementation that dispatches before policy returns now fails the suite.
3. **Medium: S10 did not prove charging behavior for omitted usage or handler failure.** Nonzero-cost fixtures now catch omitted-cost-as-zero, refund-on-failure and retained-concurrency mutations. Catalog version 1.1.0 distinguishes this stronger suite from earlier results.
4. **Medium: an adapter that never settled could hang conformance indefinitely.** Each variant now has a configurable asynchronous timeout and produces a failed result when it expires. This does not terminate blocking JavaScript or cancel unfinished adapter work.
5. **Assurance gap: MCP and package-consumer testing were too narrow.** New official-SDK tests exercise actual `tools/list` and `tools/call`. Packed packages are installed into a clean consumer; public declarations and README TypeScript examples compile with strict options, and a typed MCP consumer executes both denied and allowed calls.
6. **Release gap: publication could run from an uncommitted source tree.** Preflight now requires a clean Git checkout, aligned root/workspace versions and exact internal dependency versions before and after checks. This reduces future source drift; it cannot repair the initial release metadata.

The SDK tests also establish a deployment limit: a canceled client request can settle while the remote handler continues running. Local guard concurrency tracks the registered bridge promise. Remote concurrency, cancellation and cost ceilings need enforcement by the server or provider. The package documentation now states this explicitly and documents the core JSON envelope limits.

## Validation

- `npm run check`: builds all three packages, passes **114 tests**, and passes the clean tarball-consumer check.
- The same **114 tests pass** on Node **22.0.0**, **22.23.4**, **24.22.1** and **26.12.0** on the local macOS host. This is not evidence of a successful hosted Linux matrix.
- All **20 malicious/benign scenario variants** pass against the candidate; the added faulty-implementation regressions fail the intended variants.
- The MCP suite contains **18 passing tests**, including official SDK integration and metadata subtests.
- Node 26 coverage over the built package JavaScript reports **99.78% lines** and **93.78% branches**. Core and MCP each have 100% line coverage; coverage does not establish security correctness by itself.
- Nine release-preflight fixture tests exercise clean/dirty checkouts, version mismatches, internal dependency ranges and invalid publication locations.
- No third-party runtime dependency was added to core. The official MCP SDK packages are exact-version development dependencies only.

## Remaining gates before an overall 9/10

1. Restore GitHub Actions execution by resolving the account billing lock, then obtain a green Node 22/24/26 matrix on the reviewed commit. The [blocked main run](https://github.com/ShieldaAI/agent-guard/actions/runs/40037142502) is not successful validation.
2. Protect the release source with required checks and review. At review time, `main` has no branch protection or ruleset enforcing these gates.
3. Review and merge the hardening changes, publish a new aligned alpha version from a clean committed checkout, and verify its exact registry install, integrity, `gitHead` and release tag. The existing npm alpha remains unchanged by this audit.
4. Establish verifiable build provenance for subsequent public releases, preferably through a restricted trusted-publishing workflow. Initial registry signatures and matching hashes confirm integrity but do not attest to the build process.

The initial packages record `gitHead` `6db7631a1f9ba070b5e5c9b2a5152be0584b0622`, while their packaged READMEs match release tag commit `f7e4c77d675a6ec2fd7ab402858d49038ccc86ea`. Executable files and published integrity were verified; the discrepancy concerns documentation source traceability. See [release instructions](releasing.md) for the full boundary and process.

An alpha-quality score does not make these packages ready for unattended production privilege enforcement. Production assurance needs deployment-specific integration, enforced host isolation and credentials, and an independent security review appropriate to the application's risk.
