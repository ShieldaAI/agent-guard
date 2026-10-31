# Open-source agent security implementation status

Snapshot: 28 October 2026. The changes are local, uncommitted and unpublished on
`codex/agent-security-hardening` in all four repositories. Existing licenses remain
Apache-2.0 for Agent Guard/Security Watch and MIT for both SafeCall implementations.
No mandatory account, hosted service or private implementation was added.

## Implemented

| Project | Changes |
| --- | --- |
| Agent Guard | Shared mandatory authorization gates; typed argument normalization; opaque resource versions; encrypted single-owner SQLite executor; scoped task/admin HTTP credentials; atomic approvals and ancestor reservations; conservative crash recovery; storage quotas; bounded file/network/outbound/model adapters; managed MCP sessions and descriptor quarantine; local bounded schemas; explicit resources/prompts; memory quarantine/rollback; signed artifact provenance; governed Docker shell tool; twelve paired conformance scenarios. |
| SafeCall Python and Node | Additive buffered output validation; one finalizer for completion/repair/buffered streams; decoded/transformed-value inspection; completion/truncation checks; cancellation and upstream cleanup; admission before initial/retry/repair/stream requests; durable local reservations and conservative unknown-usage handling; matching versioned fixtures and migration documentation. |
| Security Watch | Source coverage/freshness receipts; bounded CycloneDX import; inventory/content/configuration drift; artifact origins/digests/package URLs/revisions/dependencies; declared signature/attestation/lifecycle evidence; configuration-dependent remediation guidance; recent MCP/OpenHands fixtures; supported PyPI final-release comparisons; optional review before AI news exclusion. |

The executor uses the same mandatory gates as the embedded core. Protected effects
require current grants, tool approval, tenant/recipient checks and budgets. Unknown
execution outcomes retain reservations and do not automatically retry. Recovery tests
kill processes before admission commit, after admission, during execution and after
settlement. A source revocation also follows persisted handoff edges.

The sandbox uses a preinstalled reviewed image digest, a local Linux Docker runtime,
nonroot identity, read-only image, dropped capabilities, fixed resource limits and
no network. Selected files are copied in; bounded outputs require separate review.
Signed envelopes carry sensitivity through encoded file/stdout/stderr outputs and
fresh-root imports. Neither metadata approval nor signatures establish content safety.

## Verification

| Project/check | Result |
| --- | --- |
| Agent Guard `npm run check` with the pinned Docker integration image | **194/194 tests**, zero skipped; declarations, README examples and clean installed package consumer passed. |
| Agent Guard platform gate | **11/11 tests**, zero skipped, including five required real-runtime cases on macOS with Colima/Linux Docker 29.5.2. |
| SafeCall Python | **245 tests**, **92.45% coverage**; Ruff, formatting, wheel/sdist build, Twine and clean wheel consumer passed. |
| SafeCall Node | **212 tests**; lint, formatting, types, build and clean installed package consumer passed. |
| Security Watch | **685/685 tests**, formatting/build and clean packaged CLI/public-type consumer passed. PyPI comparisons include 153 static reference cases from Python packaging. |
| Cross-repository integration | SafeCall Node called the authenticated executor/model adapter: benign response accepted, known-secret response released zero buffered chunks, next provider effect denied after budget exhaustion, costs retained. |
| npm production dependency audit | Agent Guard, SafeCall Node and Watch each returned zero reported vulnerabilities at this snapshot. This is advisory coverage, not proof that dependencies are safe. |

Security Watch's pinned PyPI comparison dependency requires **Node 24.10 or newer**;
its installed consumer was also checked on 24.10.0. The new executor requires Node
22.13 or newer. Existing package versions were not republished.

## Remaining gates and boundaries

The entire roadmap and first protected release are **not complete**. The following
work must be finished before claiming the planned deployment boundary:

1. Run and retain native Linux and Windows/WSL2 host evidence. The installed workflows
   require matching host OS, a pinned image, zero skips and named runtime cases, but
   this session validated only macOS with a Linux VM. Provision private Windows ACLs
   and test VM restart/reconnect and recovery on each platform.
2. Finish one complete networked coding-client workflow and an isolated untrusted
   MCP-server lifecycle. The governed shell, model broker and managed MCP connection
   are implemented components; a supplied MCP transport is still a host responsibility.
   The sandbox deliberately has no direct network access or provider credentials.
3. Complete an independent security review and pilot measurements. Internal agent
   review and automated tests are not that release review. Establish retention,
   backup/key rotation and operational reconciliation procedures for real deployments.
4. Extend cryptographic artifact admission beyond pinned sandbox images and signed
   local content receipts. Watch records operator-declared signature/attestation
   evidence; it does not perform cryptographic verification or independently observe
   running deployments. A patched version alone does not resolve configuration risk.
5. Implement the later distributed-worker milestone, including shared transactions,
   worker fencing, remote delegation and partition/recovery tests. The executor
   intentionally rejects a second SQLite owner; independent local ledgers are not
   distributed quotas.

SafeCall buffered modes are opt-in. Known text detectors cannot catch every encoded
or novel secret; custom string-only streams trust normal EOF as completion. Local
reservation files require POSIX and one shared local filesystem; broker integration
is the path for other environments. Python and Node retain their documented legacy
character-count units. Declared cost bounds do not replace provider/account spending
controls. Watch's unsupported PyPI prerelease/dev/post/local/epoch and complex range
forms remain unknown. None of these projects claims to prevent all prompt injections.

See [executor API/boundary](../packages/executor/README.md), [deployment and artifact
profiles](../deployment/README.md), [MCP capabilities](../packages/mcp/README.md), and
[scenario catalog](scenarios.md) for the concrete public interfaces and limits.
