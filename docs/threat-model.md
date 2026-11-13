# Threat model

Agent Guard decides whether a tool call made by an AI agent may run. This page
says who is trusted, what is assumed hostile, what the guard enforces and what it
cannot. Terms are defined in the [glossary](glossary.md).

The claim is narrow. If the host is trusted and its tool definitions and task
setup are correct, the guard applies the grants and checks to every call that
goes through it. It does not detect prompt injection, and it does not isolate
the handler, the model or the application from the operating system.

For the same material arranged by the OWASP Top 10 for Agentic Applications, see
[Risks and how Agent Guard handles them](risks.md).

## The boundary

```text
  Model output, retrieved content, tool results, caller arguments
                      (assumed hostile)
                             |
                             v
                         The host
        chooses the task; never takes identity from the model
                             |
                             v
                         The guard
      grant -> tenant -> policy -> approval -> budget reservation
                             |
                             v
                       Tool handler
           performs the one operation that was allowed
```

The host must send every protected operation through the guard. If the agent can
also reach a shell, an SDK client, a database connection, a network client or a
second Model Context Protocol (MCP) connection directly, it can go around the
guard.

## Who is trusted

The guard trusts the host: the application code that embeds it. That includes:

- The code that creates tasks, grants and parent-child relationships.
- Each tool's `parse` and `resolve` functions, which name the resource, tenant
  and recipient of a call.
- Each tool's `execute` handler and the credentials it holds. A handler that is
  allowed to run can do anything its process can do.
- The approval screen, the policy, the clock and the process memory.
- The labels the host sets: which calls read private data, and which tools
  return outside content.

A task handle is not a credential. The guard recognizes the object it issued; an
object with the same ID has no authority. Never build a task, tenant, parent or
administrator role from model-generated JSON, and never expose host
administration functions as agent tools.

The host also authenticates reviewers. An `approverId` passed to `approve` is
recorded as given. It does not prove that a person decided, or which person.

## What is assumed hostile

Assume the model may follow hostile instructions. Arguments it produces, user
text, documents, search results, tool results, tool descriptions and messages
from other agents may try to:

- call a tool that is not registered, or reach a resource that is not granted;
- claim another tenant, parent, task or administrator identity;
- widen a child task's permissions;
- change the policy, grant an approval or obtain credentials;
- send private data to a recipient that is not allowed;
- replay or alter an approved action;
- use an MCP tool whose definition changed without review;
- use up call or concurrency limits, or keep a task running forever.

None of this becomes trusted because it is valid JSON, matches a schema, comes
from an allowed domain or was written by another agent.

## What the guard enforces

Each rule applies to calls made through the guard. A call that is denied or
lacks approval never starts the handler. The exact rules are in the
[API contract](api-contract.md).

| Area | Rule |
| --- | --- |
| Tools and resources | Tool names and resources match exactly. `*` is an explicit wildcard. A tool's name or description grants nothing. A tool definition must be approved by its fingerprint before any call. After a change, the guard shows the reviewer which fields of the definition changed; the changed text is untrusted data, and the comparison says nothing about the tool's code. |
| Tenant | The tenant comes from the task. A call whose resource belongs to another tenant is refused. |
| Delegation | A child task holds the same or less than every ancestor. Revoking a parent revokes its children. |
| Approval | An approval covers one prepared action: these arguments, this resource, this policy. It works once and expires. A policy change or a tool change invalidates it. It never overrides a revoked task, a denial or the sensitive-data rule. |
| Policy | A custom policy can deny or require approval. It cannot allow what the built-in checks refuse. If it throws, the call is denied. |
| Budgets | Calls, calls in flight and cost are reserved before the handler runs, for the task and each ancestor. A call counts even if its handler fails. |
| Private data | Once a task family reads data the host marked sensitive, it cannot send anything outside, even with approval. Outbound calls need a listed recipient. |
| Secrets | Outbound arguments are searched for the literal secret values the host configured. |
| Outside content (opt-in) | Once a task family runs a tool labeled as reading outside content (`untrusted` in the API), tools set to `require_approval` need a new approval and tools set to `deny` are refused. |
| Revocation | A revoked task makes no further calls. Running handlers are asked to stop. |

The outside-content labels are the host's statement about its tools. A tool that
returns hostile text but is not labeled does not mark the family, and an injected
instruction can still steer the calls that remain allowed. The default mode is
`allow`, so nothing changes until the host sets labels.

## What the guard cannot do

| Limit | Consequence |
| --- | --- |
| It runs in the host process | Compromised host code, a hostile dependency or arbitrary JavaScript in the process can change or bypass it. |
| Handlers are trusted | An allowed handler can use every credential its process holds. The guard does not see its internal calls or sockets. |
| The guard's state is in memory | Tasks, approvals, revocations and counters end with the process and are not shared between processes. Use the executor to keep them. |
| No transaction with remote systems | Using an approval, reserving budget and performing a remote effect cannot commit together. After a crash or timeout the outcome can be unknown. |
| Cancellation is a request | A deadline or revocation cannot stop a handler that ignores its abort signal, or undo a request a remote service already accepted. |
| Labels are set by the host | Private data copied into a new, unrelated task loses its mark unless the host carries it over. |
| Secret matching is literal | Encoded, split, encrypted or paraphrased values are not found. |
| Tool review covers the definition | An unchanged MCP name, schema and description do not prove the server behaves the same. |
| Cost is bookkeeping | Reservations rely on the maximum the host declares and the usage the handler reports. Enforce the real ceiling at the provider. |

Three things follow for a deployment:

- **To keep state across restarts**, use the executor. It stores budgets,
  revocations and used approvals in its ledger and records unknown outcomes for
  a person to settle. It serves one owner process; separate guards or executors
  do not share a limit.
- **To run code or tool servers you do not trust**, add an operating-system
  boundary: restricted credentials and enforced network controls. The
  [Docker isolation profile](../deployment/README.md) is one, and the
  [MCP isolation check](guides/mcp-isolation-acceptance.md) verifies it on your
  host.
- **For MCP**, the guard's accounting ends when the client's request settles.
  The remote server may still be working. Enforce concurrency, cost and
  cancellation at the server as well.

[Support and limits](support-and-limits.md) lists the limits of each package and
what the host must do.

## Outside this model

Agent Guard does not protect against operating-system or runtime vulnerabilities,
hostile administrators, a compromised credential store, code execution inside its
own process, or operations performed outside it. It does not check that model
output is correct.

Distributed revocation, identity shared between organizations and company-wide
secret custody are not provided by any package.

## Logging decisions

Record the task, tool, resource, decision and error code for each call; the
[audit log guide](guides/audit-log.md) shows how. Keep prompts, credentials and
raw arguments out of the log. A local log is an operational record, not a signed
audit trail.

Treat a handler error differently from a denial. A denial means the handler never
started. A handler error means the effect may already have happened.

## Agent Ops (reference app)

[Agent Ops](../apps/agent-ops/README.md) is a reference review service for one
owner on Linux. It puts a browser sign-in and an agent HTTP endpoint in front of
the executor.

- **People** sign in through OpenID Connect. Each enrolled person maps to one
  operator ID, one tenant and explicit roles. Group names from the identity
  provider, browser fields, proxy headers and model output create no
  permissions. A session lasts at most 15 minutes.
- **Agents** hold a random bearer token tied to an agent ID, a tenant and a list
  of tickets. With it an agent can propose a status change and read its own
  request and receipt. It cannot approve, execute, reconcile or read other
  tickets. Keep the token in the host, outside prompts and tool arguments.
- **Self-approval.** One person can hold the requester and reviewer roles, so by
  default this is not a two-person rule. Set
  `"requests": { "forbidSelfApproval": true }` once a second reviewer is
  enrolled.

Session handling, rate limits and capacity settings are in the
[Agent Ops README](../apps/agent-ops/README.md).
