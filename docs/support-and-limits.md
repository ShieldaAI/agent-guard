# Support and limits

This page says what Agent Guard enforces, what you must do yourself, what it
does not do, and the limits of each package. Read it before you decide where the
guard sits in your system.

Related pages: the [threat model](threat-model.md) explains the assumptions, the
[API contract](api-contract.md) has the exact rules and numbers, and the
[error catalog](errors.md) lists every code. Terms are in the
[glossary](glossary.md).

## In short

Agent Guard authorizes the tool calls an AI agent makes. The model may believe a
hostile email, ticket or tool description. That belief must not give it a new
identity, credential, destination, approval or spending limit.

It limits what a misled agent can do. It does not detect prompt injection, it is
not a sandbox for your own handlers, and it has no effect on operations that do
not go through it.

No independent security assessment of Agent Guard has been done yet.

## What it enforces

These rules apply to every call that goes through the guard or the executor. A
call that is denied or lacks approval never starts the handler.

| Area | Rule |
| --- | --- |
| Tools and resources | A call needs a registered tool, an approved tool definition and a grant for the exact resource. `*` is an explicit wildcard. |
| Tenant | The tenant comes from the task. A resource in another tenant is refused. |
| Delegation | A child task holds the same or less than its parent. Revoking a parent revokes its children. |
| Approval | An approval covers one exact action, works once and expires. A changed policy or tool invalidates it. |
| Budgets | Calls, calls in flight and cost are reserved before the handler runs, for the task and each ancestor. |
| Private data | After a task family reads data marked sensitive, it cannot send anything outside, even with approval. Outbound calls need a listed recipient. |
| Secrets | Outbound arguments are searched for the literal secret values you configured. |
| Outside content (opt-in) | After a task family runs a tool labeled `readsUntrusted`, tools set to `require_approval` need a new approval and tools set to `deny` are refused. |
| Unknown outcomes (executor) | A call whose result was lost is held for a person to settle. It is never retried and its budget is never released on a timer. |
| Restarts (executor) | Budgets, revocations, marks and used approvals survive a restart. With the rollback witness, restoring an old copy of the ledger is refused. |
| Model Context Protocol (MCP) tools | A tool is callable only with an approved fingerprint of its current definition. A changed tool list stops all calls from that connection until you review again. |
| Isolated code (Docker profile) | Code runs with no network, no host credentials and no writable host mount, as a non-root user with resource limits. |

## What you must do

- **Send every protected operation through the guard.** A shell, SDK client,
  database connection, network client or second MCP connection the agent can
  reach directly is not covered.
- **Create tasks, grants and tenants in your own code.** Never take them from
  model output, and never expose administration functions as agent tools.
- **Authenticate users and reviewers.** An `approverId` is recorded as given. It
  does not prove a person decided.
- **Name resources precisely.** `resolve` must return your application's own IDs.
  A free-text name that can point at another tenant, account, file or
  destination is not enough.
- **Check again in the backend.** Restrict each handler's credentials. Enforce
  tenant, target, resource version and cost ceilings where the effect happens.
- **Set the labels.** Mark calls that read private data as sensitive, label tools
  that return outside content, and carry marks over when you copy data into a
  new task.
- **Handle unknown outcomes.** Make handlers idempotent, or be able to look up
  what happened before anyone retries.

## What it does not do

- **Detect prompt injection.** An injected instruction can still steer the calls
  that remain allowed.
- **Protect against a compromised host.** Hostile code or a hostile dependency
  in the guard's process can change or bypass it.
- **Sandbox your handlers.** An allowed handler can use every credential its
  process holds. Only the separate Docker profile isolates code.
- **Commit together with a remote system.** Using an approval, reserving budget
  and a remote effect are separate steps.
- **Force a handler to stop.** Deadlines and revocation send an abort signal. A
  handler can ignore it, and a remote service may already have acted.
- **Find every secret.** Matching is literal. Encoded, split or paraphrased
  values pass.
- **Know real spending.** Cost limits use the maximum you declare and the usage
  your handler reports.
- **Provide a signed audit trail.** Decision events and local logs are
  operational records.
- **Work across hosts.** There are no distributed quotas, no distributed
  revocation and no high availability.

## Limits by package

### The guard (`@shieldaai/agent-guard`)

| Limit | Value |
| --- | --- |
| State | In memory. It ends with the process and is not shared between processes or between guards. |
| One JSON value (arguments, result, definition) | 1 MiB, 100,000 values, 64 levels by default |
| Live approvals per action | 4 by default |
| Policy evaluations at once | 8 per task family, 64 per guard by default |
| Policy run time | 30 seconds by default |

All but the nesting depth can be changed; ranges are in the
[API contract](api-contract.md#limits).

### MCP adapter (`@shieldaai/agent-guard-mcp`)

- It covers calls made through it. It does not sandbox the server or stop
  another client from connecting to it.
- The remote server must enforce its own authorization. An approved server can
  still misbehave; reviewing a definition does not review the code behind it.
- When a call is canceled, the server may keep working. Enforce concurrency,
  cost and cancellation at the server too.
- A failed call (timeout, error reply, invalid or oversized result) fails only
  that call. Its effect is unknown and it is not retried.
- Tool schemas must fit a bounded JSON Schema profile. `format` is not
  validated. A tool whose schema does not fit is skipped and listed in
  `connection.skipped`.
- Sampling, elicitation, roots, subscriptions and MCP Apps are not supported.
- Run a server you do not trust in its own container or service identity, with
  no host socket, no secrets and no open network. The
  [MCP isolation check](guides/mcp-isolation-acceptance.md) verifies that setup.

| Limit | Default |
| --- | --- |
| Request time | 10 seconds |
| Bound operations per connection | 64 |
| One protocol message | 1 MiB |
| Inbound messages | 10,000 per 10 seconds |

### The executor (`@shieldaai/agent-guard-executor`)

- **One owner.** One process owns one ledger on a local file system. A second
  process is refused.
- **Tool approvals and prepared actions do not survive a restart.** Register and
  approve tools again.
- **The key is yours to keep.** The ledger is encrypted with a 32-byte key you
  supply. Without the key the ledger cannot be read.
- **Restoring an old ledger rolls back authority.** Enable the rollback witness
  on a new ledger and keep the witness outside your backup and restore path; see
  the [ledger rollback guide](guides/ledger-rollback.md).
- **Repair needs surviving copies.** Recovery after storage loss needs the
  witness or mirror and its keys. Losing both at once cannot be repaired.
- **File permissions on Windows are yours to set.** On POSIX systems the
  executor checks that its files are private; on Windows it cannot.
- **The task server listens on `127.0.0.1` only.** It has no TLS and no login.
  Put an authenticated transport in front of it for a remote agent.
- **The inventory observer is experimental.** It makes no promise about
  admission latency while it is polled often; the collector's default interval
  is five minutes.

| Limit | Default |
| --- | --- |
| Ledger size (decoded) | 16 MiB; 1 MiB to 64 MiB |
| New work stops | 1 MiB below the ledger size (an eighth below it for ledgers under 8 MiB) |
| Records | 10,000 |
| Settled receipts kept per task family | 64 |
| Recent audit events | 256 per tenant, 1,000 in total |
| Memory value | 64 KiB; 128 versions per entry |
| Archives | 4,096 per ledger, 256 MiB in total |
| Task server | 600 requests a minute per token, 6,000 in total for task routes, 32 in flight (4 kept for admin routes) |

The rest are in the [API contract](api-contract.md#executor-shieldaaiagent-guard-executor).

### Docker isolation profile (`.../sandbox`)

- Verify it on each kind of host you run. A result on Linux says nothing about
  another host. Docker on Windows needs its own check.
- It isolates the code it runs. It does not isolate handlers that run in your
  own process.

See the [Docker isolation profile](../deployment/README.md).

### Agent Map (`@shieldaai/agent-map`, experimental)

- It is read-only. It never grants permission and never runs a call.
- It lists only agents a person declared in a host manifest. Its discovery views
  are leads to follow up, not the result of a scan.
- It needs a Neo4j database filled by the Cartography collector, which has its
  own version and deployment.
- The browser viewer is part of the source tree and is not published to npm.

### Agent Ops (reference app)

- One owner, on Linux. It is part of the source tree, not an npm package.
- Its backend is a local ticket store. Connecting Jira, Linear or another system
  needs an adapter you write, with its own authorization and receipts.
- It refuses new work when it reaches its configured capacity. Capacity settings
  never widen an agent's grants or budget.
- Finished requests can be moved to history files, up to 10,000 segments. See
  the [company history guide](guides/company-history.md).

Sessions, tokens and rate limits are in the
[Agent Ops README](../apps/agent-ops/README.md).

## Supported platforms

| Component | Requirement |
| --- | --- |
| Guard, MCP adapter, scenarios | Node.js 22 or later |
| Executor, Agent Map | Node.js 22.13 or later |
| Rollback witness, key custody and recovery tools, manifest file loader | Linux and macOS |
| Agent Ops and the production image | Linux |
| Docker isolation profile | Verified on Linux; verify other hosts yourself |
| Browser apps (Agent Ops, Agent Map viewer) | Tested in Chromium, Firefox and WebKit |

Continuous integration runs on Linux with Node.js 22, 24 and 26, and on macOS
and Windows with Node.js 24.

The packages do not bundle Node.js. Run them on a patch release that has the
current security fixes.

## Stability by package

| Package | Stability |
| --- | --- |
| `@shieldaai/agent-guard` | Stable |
| `@shieldaai/agent-guard-mcp` | Stable |
| `@shieldaai/agent-guard-scenarios` | Stable. The scenario catalog has its own version. |
| `@shieldaai/agent-guard-executor` | Stable, except `/inventory` (experimental) and `/internal` (no promise). Every 1.x executor opens ledgers written by earlier 1.x versions and by `0.1.0-alpha.3`. |
| `@shieldaai/agent-map` and the Cartography integration | Experimental. Published as 1.0.0 but outside the compatibility promise. |
| Agent Ops | Reference app in the source tree |

Stable exports follow semantic versioning from 1.0.0. Experimental exports can
change in a minor release. There is no long-term-support line; security fixes go
into the current release.

## Before you deploy

1. List every way the agent can read, write, send, start a process, call a
   provider or start another agent. Remove or isolate each path that does not go
   through the guard.
2. Authenticate reviewers, and show them the action read back from the guard or
   the executor, not a description from the agent.
3. If you use the executor, back up the ledger and its key, and restore them in
   a test. Keep the rollback witness outside that restore path.
4. Send denials, unknown outcomes and quarantined MCP connections to someone who
   will act on them.
5. If you use the Docker profile, run its verification on your own host.
6. Run the [scenarios](scenarios.md) against your integration.

## Reporting problems

Report vulnerabilities privately as described in [SECURITY.md](../SECURITY.md).
Include the affected version and a reproduction with made-up data; do not send
real credentials or customer data.
