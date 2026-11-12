# Risks and how Agent Guard handles them

This page maps Agent Guard to the
[OWASP Top 10 for Agentic Applications 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/).
For each risk it says what Agent Guard does, which package does it, and what stays with
you. It is a summary: [Support and limits](support-and-limits.md) and the
[threat model](threat-model.md) are the full statements. [Standards and further
reading](standards.md) relates the same controls to other frameworks, and the
[glossary](glossary.md) defines the terms.

Agent Guard controls the **effect** of a tool call, not what the model believes. It does
not detect prompt injection. Every protection below applies only to calls routed through
the guard; a shell, SDK client or second connection that the agent can reach directly is
outside it.

## Packages

| Short name | Package | Role |
| --- | --- | --- |
| core | `@shieldaai/agent-guard` | In-process authorization: grants, tenants, delegation, approvals, budgets, sensitivity and outside-content labels. |
| mcp | `@shieldaai/agent-guard-mcp` | Routes MCP tools, resources and prompts through core, with reviewed metadata and bounded schemas. |
| executor | `@shieldaai/agent-guard-executor` | Durable version of core: encrypted ledger, task tokens, governed memory, isolated workloads, inventory export. |
| scenarios | `@shieldaai/agent-guard-scenarios` | Thirteen paired hostile and benign test cases (S01 to S13) you run against your own integration. |
| map | `@shieldaai/agent-map` with the Cartography collector | Read-only inventory of declared agents, their grants, resources and identities, plus leads to activity and cloud identities nobody declared. It never grants or blocks anything. |

## Risk by risk

### ASI01 Agent Goal Hijack

Hostile text in an email, ticket, web page or tool result redirects the agent.

- **What Agent Guard does.** The host fixes each task's tools, resources and tenant
  before the model runs, so a redirected agent can only use what that task was granted.
  Arguments are validated and frozen. With the opt-in outside-content labels, once a task
  family runs a tool marked `readsUntrusted`, tools in `require_approval` mode need a
  fresh review, tools in `deny` mode are refused, and approvals given for those tools
  before the read stop working.
- **Package.** core; executor keeps the mark across restarts; mcp can mark a whole
  connection; scenarios S13 tests it; map flags agents that can read private data, read
  outside content and send out (the "dangerous three").
- **What stays with you.** The labels are your claim about each tool, and the default
  mode is `allow`. An unlabelled tool that returns attacker text does not mark the task.
  An injected instruction can still steer calls that remain allowed.
- **Does not cover.** Detecting the injection itself.

### ASI02 Tool Misuse and Exploitation

The agent uses a permitted tool in a way nobody intended.

- **What Agent Guard does.** Default deny: a call needs a grant for that tool and
  resource (or an explicit `*` resource grant) on the task and every ancestor. Tenant, control-plane and recipient checks run before
  the handler. Destructive calls can require approval of the exact prepared action.
  Budgets cap calls, concurrency, cost and time. A task that touched sensitive data
  cannot send externally, and configured secrets are scanned in outbound arguments.
- **Package.** core; executor makes approval consumption (replay protection), budgets
  and revocation durable, while a restart invalidates pending prepared actions and tool
  approvals; scenarios S01, S03, S04, S07, S10, S11.
- **What stays with you.** Register tools correctly and derive the real resource,
  recipient and tenant from validated arguments. Restrict the handler's own credentials
  at the backend: once a call is allowed, the handler can use everything its process can.
- **Does not cover.** Data you did not mark sensitive, secrets that are encoded or split
  (only exact configured values are matched), or what a tool does internally once allowed.

### ASI03 Identity and Privilege Abuse

An agent acts with someone else's identity or more privilege than it was given.

- **What Agent Guard does.** Task handles are recognized by object identity, not by a
  printed ID, and the tenant comes from the host. A child task gets only the grants the
  host lists for it, and each must already be held by every ancestor; anything wider is
  refused. Revoking a parent revokes its descendants. The executor
  authenticates each task with its own bearer token across processes.
- **Package.** core; executor (task tokens, durable revocation); mcp (verified HTTP
  credentials, redirects refused); scenarios S02, S09; map shows tool identities whose
  S3 reach in the enrolled AWS account is wider than the grants bind.
- **What stays with you.** Authenticate users and reviewers. Never accept a task handle,
  tenant or parent from model output.
- **Does not cover.** Agent identity across machines, or custody of your secrets.

### ASI04 Agentic Supply Chain Vulnerabilities

A tool or MCP server changes under you.

- **What Agent Guard does.** A tool's registered metadata gets a fingerprint that the
  host must approve; a changed tool is refused until reviewed, and approving metadata
  never authorizes an action. Each MCP registration carries a `descriptorDigest` that
  stays the same while the server advertises the same definition, so you can record it
  when you review a tool and approve only a matching one after a restart. MCP schemas are
  compiled under strict bounds, including refusal of regular expressions with unbounded
  backtracking. The executor pins image
  digests, artifact bytes and enrolled builders for admitted build artifacts.
- **Package.** core (fingerprint approval); mcp (drift quarantine, bounded schemas);
  executor (artifact admission); scenarios S06.
- **What stays with you.** Review each definition before you approve it, and store its
  digest. Vet the servers and dependencies you install.
- **Does not cover.** A server that changes what it does without changing its definition,
  the npm packages you install, model files, or a compromised dependency running inside
  the guard's own process.

### ASI05 Unexpected Code Execution (RCE)

The agent gets code to run where it should not.

- **What Agent Guard does.** The guard itself is not a sandbox. The executor's optional
  Docker profile runs untrusted code with no network, no host credentials, no management
  socket and no writable host mount, as a non-root user with dropped capabilities,
  resource limits and exports that are bounded and reviewed.
- **Package.** executor (`@shieldaai/agent-guard-executor/sandbox`).
- **What stays with you.** Use that profile, or an equivalent boundary, for any tool that
  runs generated or downloaded code. Ordinary in-process handlers are not isolated.

### ASI06 Memory & Context Poisoning

Bad content written into memory or shared context steers later work.

- **What Agent Guard does.** The executor's governed memory records where each entry
  came from, versions writes, carries sensitivity, and supports quarantine and rollback.
  Sensitivity and the outside-content mark are shared by the whole task family and never
  reset. An entry written after its author read outside content carries that mark to
  whoever reads it. Retrieved or stored data never issues a grant or approves an action.
- **Package.** executor (governed memory); core (family-wide sensitivity and
  outside-content marks).
- **What stays with you.** Mark sensitive reads in your resolvers before the data can
  affect another action. Core alone has no memory store.
- **Does not cover.** Spotting poisoned content, or memory kept anywhere else (your
  vector store, search index or files).

### ASI07 Insecure Inter-Agent Communication

Agents trust each other's messages.

- **What Agent Guard does.** A message from another agent is data: it cannot carry
  authority. Authority moves only through tasks the host creates. Delegation narrows
  grants, recipients, budgets and deadlines. A handoff is a new root task with whatever
  grants the host gives it; it must stay in the source's tenant, and it inherits the
  source's sensitivity and outside-content marks. Revocation follows both.
- **Package.** core (delegation); executor (handoffs, lineage in the ledger); scenarios
  S02.
- **What stays with you.** Delegation is local to one executor. Authenticating agents
  across machines, and the transport between them, is yours.
- **Does not cover.** Signing, encrypting or authenticating messages between agents.

### ASI08 Cascading Failures

One fault or runaway loop spreads.

- **What Agent Guard does.** Calls, concurrency and maximum cost are reserved across a
  task's ancestors before dispatch. Deadlines refuse new calls and signal running
  handlers to stop (cancellation is cooperative). With the executor, a lost or ambiguous
  result leaves that action `UNKNOWN` and keeps its reservation until an operator
  reconciles it; core charges the declared maximum cost. Neither retries the action or
  repeats an effect to find out whether the first one happened. The executor isolates tenants' retention and limits
  request rates on its task server.
- **Package.** core; executor; scenarios S10.
- **What stays with you.** Enforce cost ceilings at the provider too. There are no
  distributed quotas: separate guard instances do not share a limit.

### ASI09 Human-Agent Trust Exploitation

A person approves something other than what then happens.

- **What Agent Guard does.** An approval binds one prepared action: its tenant,
  arguments, resource version and expiry. It is single use, cannot be moved to another
  action, and never overrides a denial or a revoked task. Changing the arguments after
  approval changes nothing, because the stored action is what runs. With the executor,
  the review screen can read what an action ID denotes from the ledger
  (`preparedAction()`), not from the party asking for approval.
- **Package.** core; executor (durable replay protection); scenarios S05, S12. The
  Agent Ops reference app adds signed-in reviewers and an optional rule that a requester
  cannot approve their own request.
- **What stays with you.** Authenticate the reviewer and show them the prepared action
  itself. An `approverId` string is not proof that a person decided.
- **Does not cover.** A person approving a harmful action that is shown accurately, or
  reviewers who approve without reading.

### ASI10 Rogue Agents

An agent keeps operating outside what anyone intended, or nobody knows it exists.

- **What Agent Guard does.** Any task can be revoked with its descendants, and with the
  executor an acknowledged revocation survives restart. Budgets and deadlines bound what
  a task can do before anyone notices. The map lists declared agents with their owners,
  grants, resources and changes between snapshots, and flags declared paths around the
  guard. For an all-teams reader it also gives two leads to agents nobody declared: tasks
  and callers that ran through an enrolled executor without a declared agent, and IAM
  roles and users of an enrolled AWS account that no declared agent names.
- **Package.** core and executor (revocation, budgets); scenarios S08; map (inventory,
  discovery leads).
- **What stays with you.** An agent is on the map only after a person declares it (see
  [how agents get onto the map](guides/agent-cartography.md#how-agents-get-onto-the-map)).
  The leads are candidates to review, not findings: they cover only activity through the
  guard and identities in enrolled AWS accounts. An agent that uses neither is not seen.
  Nothing here scans infrastructure, code or networks, or detects unusual behaviour.

## What no package covers

- Detection of prompt injection or of unusual agent behaviour.
- A compromised host, operating system, dependency or credential store.
- Calls the agent can make without going through the guard.
- Encoded, split or paraphrased secrets: only configured literal values are scanned.
- A signed, tamper-proof audit trail, distributed quotas or high availability.
