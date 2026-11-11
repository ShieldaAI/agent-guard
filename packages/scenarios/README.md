# @shieldaai/agent-guard-scenarios

**Version 0.1.0** is the first non-prerelease version. It makes no 1.x API
compatibility or long-term-support promise. The
[release notes](https://github.com/ShieldaAI/agent-guard/blob/main/docs/releases/0.1.0.md)
record the verified scope, known limits and post-release follow-ups.

Test AI agent tool authorization with paired malicious and benign conformance fixtures for the Agent Guard public API. Node.js 22+, ESM.

**Risks tested** ([OWASP agentic top 10 mapping](https://github.com/ShieldaAI/agent-guard/blob/main/docs/risks.md)): the thirteen scenarios
exercise goal hijack limits (ASI01: S13), tool misuse (ASI02: S01, S03, S04, S07, S10,
S11), identity and delegation (ASI03, ASI07: S02, S09), tool metadata changes (ASI04:
S06), bounded work (ASI08: S10), exact approval (ASI09: S05, S12) and revocation (ASI10:
S08). They test your integration's behaviour; they do not certify a deployment.

Install with `npm install @shieldaai/agent-guard-scenarios`. The synthetic
fixtures need no provider key or external service. See the
[package selection guide](https://github.com/ShieldaAI/agent-guard/blob/main/docs/package-guide.md)
for related execution and MCP packages.

```ts
import { runConformance, scenarioCatalog } from '@shieldaai/agent-guard-scenarios';

const report = await runConformance();
console.log(report.passed, report.passedCases, report.caseCount);
console.table(report.results);
console.log(scenarioCatalog);
```

Run selected scenarios with `runConformance({ scenarioIds: ['S05', 'S08'] })`. The default suite executes malicious and benign variants of all thirteen scenarios. It checks handler invocations and synthetic effects, not merely decision objects. The built-in fixtures use no credentials, model calls, network services or destructive operations. A custom adapter is responsible for its own I/O.

The scenarios cover unauthorized tools/resources, delegation, protected administration, sensitive export, action-bound approval, metadata drift, outbound secrets/canaries, revocation/control failures, tenants, budgets, normalized typed arguments, resource-version checks and sends after reading outside content. The [scenario specification](https://github.com/ShieldaAI/agent-guard/blob/main/docs/scenarios.md) explains each boundary.

Rejections are recognized with `isGuardError()`, so a guard built from a different installed copy of `@shieldaai/agent-guard` still passes. `catalogVersion` is a plain semver string. The catalog version identifies the executed acceptance checks independently of the package version; compare reports using their `catalogVersion`. Version `1.3.0` retains S01–S12 and adds S13 (sends after reading outside content), for thirteen scenario identifiers and twenty-six paired cases. A pass from an older catalog does not establish coverage of newly added assertions.

S11 checks that the trusted `ToolDefinition.parse` rejects wrong types, unknown or missing fields, invalid ranges and invalid or asynchronous parser results before resource resolution. The benign case verifies that normalized arguments reach resolution, both policy evaluations, approval and execution; later mutations of caller or parser-owned objects cannot change the approved effect. The core does not interpret `inputSchema` automatically: the host must supply a suitable synchronous parser.

S12 binds the resolver's `resourceVersion` to the immutable prepared action and approval. A synthetic trusted handler compares the approved version with current state immediately before its write. Version forgery and approval transfer must fail before dispatch; a genuine stale version enters the handler, consumes its attempt and produces no write. The benign pair approves and writes two successive versions separately. Real services must implement the comparison atomically with their side effect. This scenario does not claim the core locks or refreshes external resources.

To exercise a compatible implementation, supply `createGuard(options)` in the options object. The factory must honor the provided clock and secret configuration and return the structural `GuardLike` API. Denials use the exported `GuardError` and its documented reason codes. Each fixture receives an isolated instance; no shared factory state is required.

Each malicious or benign variant has a five-second asynchronous timeout. Override it with `caseTimeoutMs`, a positive integer up to `2147483647`. A timed-out variant receives a failed result and the runner continues with the next variant. The timer cannot interrupt blocking JavaScript or cancel unfinished adapter work; an adapter may retain resources or continue running after its result is reported. Use process isolation if the implementation under test needs a hard execution limit.

A passing report applies to these fixtures in one process. It is not a security certification, injection-detector benchmark, MCP transport test or proof that a production agent cannot bypass its integration. Errors after actual handler invocation are tested separately from denials that must prevent invocation.

Apache-2.0. Copyright 2026 ShieldaAI contributors.
