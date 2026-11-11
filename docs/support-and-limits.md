# Support and limits

This page states what Agent Guard protects, what it leaves to the host and the
deployer, and the known limits of each package. Read it before you choose a
deployment boundary. The [threat model](threat-model.md) gives the detailed
assumptions, the [API contract](api-contract.md) gives the exact rules, and the
[error catalog](errors.md) lists every denial and failure code.

## Summary

Agent Guard is Apache-2.0 software that authorizes the tool calls an AI agent
makes. Its design decision is to mediate the effect: the model may believe a
hostile email, ticket, tool description or another agent, but that belief must
not give it a new identity, credential, destination, approval or spending limit.

The security claim is narrow. Given a trusted host, correct tool definitions and
trusted task context, the executor applies the configured grants and checks to
calls made through it. It does not detect all prompt injection, isolate ordinary
in-process handlers, or protect operations performed outside the wrapper.

Companies operate their own installation. They provide their own records,
identity provider, credentials, TLS and storage. A product release does not
certify an unknown installation.

`0.1.0` does not promise a 1.x API contract, long-term support or production
certification.

[Risks and how Agent Guard handles them](risks.md) maps these protections to the OWASP
Top 10 for Agentic Applications and names the package for each.

## Maturity by package

| Package or component | Maturity | Notes |
| --- | --- | --- |
| `@shieldaai/agent-guard` (core) | stable | 1.0 target. In-memory guard for one process. |
| `@shieldaai/agent-guard-mcp` | stable | 1.0 target. Routes MCP tools, resources and prompts through the same guard; not a second policy engine. |
| `@shieldaai/agent-guard-scenarios` | stable | 1.0 target. Synthetic acceptance scenarios. |
| `@shieldaai/agent-guard-executor` | not yet stable | Planned for 1.0 after the storage work. Single-owner durable ledger, task API, governed memory and Docker workload isolation. |
| Inventory observer (`startInventoryServer()` in the executor) | experimental | No admission-latency promise under frequent polling. |
| `@shieldaai/agent-map` and the Cartography integration | experimental | Read-only inventory. The React/Cytoscape viewer is private and not published. Python Cartography has its own version and deployment process. |
| Agent Ops (`apps/agent-ops`) | reference app | Single-owner Linux service in the source deployment, not an npm package. |

## What Agent Guard enforces

These checks apply to calls that go through the executor. A denied or unapproved
call never starts the handler.

**Tools and resources.** Tool names and resources match exactly; resource `*` is
an explicit wildcard grant. Tool names and descriptions cannot grant authority.
Registered metadata needs host approval. Arguments are validated and frozen, and
extra authority fields are rejected. Coarse tool scope is checked before trusted
parsing and resolution callbacks run. Custom policy can only tighten the
mandatory checks.

**Identity and delegation.** Task handles are recognized by object identity, not
by a printed ID. Tenant identity comes from the host. A child task's authority is
the intersection of the applicable grants, and revocation follows ancestry.
Delegation is local to one executor and its shared context.

**Outside content (opt-in).** Tools labelled `readsUntrusted` mark their task
family `untrusted` once they run. After that, tools in `require_approval` need a review
and tools in `deny` are refused, and approvals given before the read are invalid. The
labels are the host's claim; this limits what a fooled agent can do but does not detect
prompt injection. See the [threat model](threat-model.md#outside-content).

**Exact approval.** An approval binds the tenant, arguments, resource version,
expiry and, for isolated workloads, the exact staged bytes. It is single use, and
expiry is checked before dispatch. A policy change invalidates existing prepared
actions and approvals. Approval does not override a revoked task, an explicit
denial, sensitive-context restrictions or a failed resource check. Core rejects a
clock that moves backwards. An empty or closed review never means yes.

**Budgets and concurrency.** Admission reserves calls, concurrency and the tool's
declared maximum cost before dispatch, across the task's ancestors. Calls that
reach a handler count even when the handler fails. Concurrency stays reserved
until the handler settles. Policy callbacks are bounded per task family and
globally. Costs use nonnegative safe integer units chosen by the host.

**Sensitive data and egress.** A monotonic sensitive flag is shared across a
task family. Once set by a trusted resolver, that context cannot perform external
sends, even with approval. External actions require an explicitly allowed
recipient. Configured literal secrets are scanned in outbound object keys and
string values.

**Unknown outcomes.** A lost or ambiguous result stops the run and keeps the
reservation. Recovery uses a trusted backend receipt. The guard never dispatches
another effect to learn whether the first one happened, and never releases budget
on a timer.

**Durable executor** (optional). It adds cross-process authentication, durable
approval replay protection, persisted budgets and an encrypted single-owner
SQLite ledger. Acknowledged revocation survives restart. With the independently
retained rollback witness enabled, restoring a stale ledger fails closed. Governed
memory keeps provenance, sensitivity, quarantine and rollback across reopening.

**Isolated workloads** (optional Docker profile). Untrusted code runs with no
network, host credentials, management socket or writable host mount, as nonroot
with dropped capabilities, resource limits and bounded reviewed exports. File
capture constrains each path lookup, and the broker checks the approved version
against the exact buffers sent to the guest.

**MCP.** Tool metadata generations, image digests, artifact bytes and enrolled
builders are pinned. Drift is quarantined until reviewed; approving metadata does
not authorize an action. A verified MCP session closes before decoded strings
containing the enrolled raw token reach SDK consumers.

**Agent Map.** It is read-only evidence for the viewer's authorized scope, and it lists
only agents a person declared in a host manifest. Its discovery views are leads for an
all-teams reader, not a scan and not findings. It
never grants permission, and an observation is never presented as an effective
grant or a confirmed effect. Authentication loss clears protected data.

## What it does not do (host responsibilities)

**First deployment step:** list every way the agent can read, write, send, spawn a
process, call a provider or start another agent. Remove or isolate unmediated
paths. A direct shell, SDK client, database connection, network client or
alternate MCP connection with the same credentials bypasses the guard.

The host must:

- Authenticate users and reviewers. An `approverId` passed to the approval API is
  not proof of a human decision or of a second person.
- Create task handles, grants, tenants and parent relationships in trusted code.
  Never accept them from model output, and never expose administration functions
  as agent tools.
- Register tools correctly and derive canonical resources, recipients and tenants
  from validated arguments. Free-text names that can alias another tenant,
  account, file or destination are not sufficient.
- Route every protected operation through the executor, including MCP traffic.
- Restrict handler credentials and enforce tenant, target, resource version,
  credential scope and cost ceilings at the backend or provider.
- Mark sensitive access before that data can affect another action, and carry
  labels across reuse outside an existing task family.
- Provide idempotency or reconciliation for any retry of a side effect.

Agent Guard does not provide:

- Protection from a compromised host, an untrusted dependency or arbitrary code
  running in the guard's process. Once allowed, a handler can use all authority
  available to that process.
- A sandbox for ordinary in-process handlers, a network firewall or isolation of
  the model or application from the operating system.
- A distributed transaction. Approval, budget reservation and a remote side
  effect cannot commit as one operation.
- Forced cancellation. Deadlines and abort signals are cooperative and cannot
  retract a request already accepted by a remote service.
- Complete secret or data-flow detection. Encoded, split, encrypted or
  semantically equivalent data can evade checks; literal scanning alone does not
  establish confidentiality.
- A spending oracle. Cost limits depend on trusted upper bounds and reported
  usage.
- A signed, tamper-proof audit trail. In-memory events and local logs are
  operational evidence.
- Distributed quotas or revocation, high availability, federated agent identity,
  company-wide secret custody, or protection against OS/runtime vulnerabilities,
  malicious administrators or compromised credential stores.

The core keeps task state, approvals, revocation and counters in memory.
Restarting or creating another guard is not continuity of the same security
state, and separate in-memory guards do not share a limit.

The deployer must also enroll real identities, tools and paths, test its own
storage and backup custody, route alerts, size resources, and validate its
operators and model/provider integration. The
[deployment validation checklist](archive/protection-acceptance.md#deployment-validation-checklist)
lists the evidence to collect on the enrolled target.

## Durable executor limits

- One trusted owner. The production profile uses local Linux POSIX storage. There
  is no HA or distributed quota.
- Repair requires surviving independent witnesses or mirrors and their keys. A
  simultaneous loss or rollback of those domains cannot be repaired. Crash and
  file-loss tests do not prove physical power-loss durability on a company's
  storage.
- Legacy stores need explicit recovery enrollment. Setup labels do not claim that
  a backup exists or that a recovery drill occurred.
- Sustainable ticket history is the single-root, no-memory profile. Its history
  closure is capped at **10,000 segments** for backup, mirror enrollment and
  repair. Switch to a reviewed replacement adapter before that ceiling; surviving
  mirrors do not remove it. Existing over-cap history refuses startup.
- Other SDK archives keep finite safe-stop limits, and full-chain verification
  grows with history. Raising capacity does not guarantee memory or latency for
  every maximum-sized combination. See the
  [executor README](../packages/executor/README.md) for exact limits.
- Historical key escrow remains necessary. Active-key retirement does not destroy
  off-host historical copies or find backups outside the enrolled catalog.
- Fixed `REQUEST_TIMEOUT` errors from the task HTTP server do not cause automatic
  retries. Its request scheduling is not a fairness or real-time guarantee.
- Docker isolation must be verified on each claimed host profile. Windows Docker
  isolation is a separate candidate profile that needs its own evidence.
- The inventory observer is experimental. 0.1.0 does not support running the
  observer-owning service on one logical CPU with 250 ms polling. Admission
  overhead measured under 250 ms polling is evidence for the recorded runner only;
  the collector defaults to five minutes. The optional `linux-background` worker
  scheduling lowers only the observer worker's JavaScript-thread priority, by up
  to five nice points capped at 19. It gives no GC, helper-thread or real-time
  guarantee.

## MCP limits

- The wrapper mediates only calls made through it. It does not sandbox the server
  or stop a client from opening another connection.
- A remote server must enforce its own resource authorization. An approved peer
  can still lie or misuse its own authority.
- The SDK can reject the bridge promise on cancellation before the remote server
  stops. Local concurrency and cost settle with the bridge, so enforce remote
  concurrency, cost ceilings and cancellation at the server or provider.
- A stable name, schema or description does not prove the server is safe or
  unchanged.
- A failure local to one call (timeout, abort, error reply, invalid or oversized
  result) fails only that call; connection-level failures quarantine every
  operation until `refresh()` and re-approval. The effect of a failed call is
  unknown and is never retried.
- Tool schemas use a bounded JSON Schema profile. `format` is not validated,
  `pattern` is accepted only with bounded backtracking, and a schema outside the
  profile skips that one operation (listed in `connection.skipped`).
- Passing linked-transport tests do not establish HTTP/stdio transport security,
  authentication or remote-server isolation.
- Hostile peers must run under the documented isolation profile: a separate OS or
  service identity with no host socket, raw SDK, secrets, broad filesystem or
  ambient network, and a pinned image or endpoint. See the
  [MCP isolation procedure](guides/mcp-isolation-acceptance.md).

## Agent Ops (reference app) limits

- One owner on Linux. Only Linux is supported by the production CLI; POSIX library
  tests also run on macOS. It is part of the source deployment, not an npm package.
- The bundled backend is a local ticket store. There is no live Jira, Linear or
  other third-party connector; connecting one needs a separately implemented
  adapter with its own authorization, conditional writes and receipts.
- No HA, distributed quota or universal model-resistance claim.
- It fails closed at its configured capacity. Capacity settings never increase an
  agent's grants or budget. The fixed 10,000-segment history limit above applies.
- It starts no inventory observer.
- Session, agent-token and rate limits are described in the
  [threat model](threat-model.md#agent-ops-reference-app). Capacity defaults and
  operations are in the [Agent Ops README](../apps/agent-ops/README.md) and the
  [deployment runbook](../deployment/production/README.md).
- Automated browser and accessibility checks are regression evidence, not a
  representative human usability study.

## Supported platforms

- **Node.js:** core, MCP and scenarios require Node 22 or later; the executor and
  Agent Map require 22.13.0 or later. CI runs Linux on Node 22, 24 and 26, and
  macOS and Windows on Node 24.
- **Agent Ops and the production image:** Linux only. Recovery checks run on
  ARM64 and AMD64.
- **Docker isolation:** verified on Linux by a required gate that refuses skipped
  checks. Every other host profile, including Windows Docker, needs its own
  unskipped evidence; Linux results do not extend to other hosts.
- **Browsers:** Agent Ops and Agent Map are checked in Chromium, Firefox and WebKit.
- **Node security releases:** supply-chain acceptance (R5) is withheld until the
  November 2026 Node HIGH security issues are reviewed. Company deployments of the
  production image must adopt the fixed Node runtime once it is released.

## Verification status

Tests, browser scans and internal category judgments are evidence for their
recorded fixtures and profile. They are not a certification, an ASVS assessment,
a penetration test or a guarantee of safety. There is no aggregate production
score. No company pilot, representative operator study, paid live-provider trial
or independent human security assessment has been completed; disposable fixtures
are labeled synthetic. See the
[historical assessment](archive/protection-assessment.md),
[requirements and design](archive/protection-design.md) and
[production readiness record](archive/production-readiness.md).

## Reporting problems

Report vulnerabilities privately as described in [SECURITY.md](../SECURITY.md).
Include the affected version and a synthetic reproduction; do not include real
credentials or customer data. Security fixes target the current maintained
release.
