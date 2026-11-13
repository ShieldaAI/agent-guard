# API contract

This is the reference for the stable API of Agent Guard 1.0.0: the types, the
methods and the exact rules each package applies. For a first example, start with
the [tool-permissions walkthrough](guides/tool-permissions.md). Terms are defined
in the [glossary](glossary.md), and every error code is listed in the
[error catalog](errors.md).

| Package | Section | Stability |
| --- | --- | --- |
| `@shieldaai/agent-guard` | [Core](#core-shieldaaiagent-guard) | stable |
| `@shieldaai/agent-guard-mcp` | [Model Context Protocol (MCP) adapter](#mcp-adapter-shieldaaiagent-guard-mcp) | stable |
| `@shieldaai/agent-guard-executor` | [Executor](#executor-shieldaaiagent-guard-executor) | stable, except `/inventory` (experimental) and `/internal` |
| `@shieldaai/agent-guard-scenarios` | [Scenarios](#scenarios-shieldaaiagent-guard-scenarios) | stable |
| `@shieldaai/agent-map` | [Agent Map](#agent-map-shieldaaiagent-map) | experimental |

Stable exports follow semantic versioning. Experimental exports can change in a
minor release.

## Core: `@shieldaai/agent-guard`

The host creates one `AgentGuard` and keeps it. Give the model a function that
calls `prepare` and `execute` for its task, and nothing else: never the guard
object, a task handle or an approval method.

The guard keeps all state in memory for the lifetime of that object. It
recognizes task handles and prepared actions by object identity, so a copy with
the same ID carries no authority.

### Exports

`AgentGuard`, `GuardError`, `GuardErrorCode`, `GuardErrorCatalog`, `isGuardError`,
`InvalidJsonError`, `monotonicClock` and the types below.

`@shieldaai/agent-guard/internal` holds building blocks shared with the other
packages (`PolicyAdmission`, `assertActionAuthority`, `containsLiteralSecret`,
`immutableJson`, `canonicalJson`, `digestJson`). It has no compatibility promise.

### Types

```ts
type Json = null | boolean | number | string | readonly Json[] | { readonly [key: string]: Json };

interface Capability {
  tool: string;
  resources: readonly string[]; // exact IDs; '*' means every resource of this tool
}
interface Budget {
  maxCalls: number;      // calls that reach a handler
  maxConcurrent: number; // calls in flight at once
  maxCost: number;       // nonnegative safe integer, in units the host chooses
  deadline: number;      // clock milliseconds
}
interface TaskOptions {
  id: string;
  principalId: string;
  tenantId: string;
  grants: readonly Capability[];
  budget: Budget;
  allowedRecipients?: readonly string[];
  allowControlPlane?: boolean;
}
interface TaskIdentity { id: string; principalId: string; tenantId: string }
interface TaskHandle { readonly id: string }

type UntrustedContextMode = 'allow' | 'require_approval' | 'deny';

interface ToolDefinition {
  name: string;
  description: string;
  inputSchema?: Json;         // fingerprinted, not evaluated; validate in parse()
  metadata?: Json;            // fingerprinted
  requiresApproval?: boolean; // every call needs approve()
  controlPlane?: boolean;     // only tasks with allowControlPlane may call it
  maxCost?: number;           // reserved before each call; default 0
  readsUntrusted?: boolean;   // the tool returns outside content
  untrustedContext?: UntrustedContextMode; // what this tool does once the family is untrusted
  sendsExternal?: boolean;    // false is enforced; omitted means unknown
  parse?(input: Json): Json;  // synchronous; validates and normalizes arguments
  resolve(args: Json, task: Readonly<TaskIdentity>): ResolvedAction; // synchronous
  execute(
    args: Json,
    context: { signal: AbortSignal; action: Readonly<Action>; task: Readonly<TaskIdentity> },
  ): Promise<ToolResult> | ToolResult;
}
interface ResolvedAction {
  resourceId: string;
  tenantId: string;
  external?: boolean;       // the call sends data outside
  recipient?: string;       // required when external is true
  sensitive?: boolean;      // the call reads private data
  resourceVersion?: string; // bound into the action and its approval
  untrusted?: true;         // this call returns outside content; can only be set, never cleared
}
interface ToolResult {
  value: Json;
  actualCost?: number; // safe integer from 0 to the tool's maxCost
}
interface Action extends ResolvedAction {
  tool: string;
  args: Json;
  toolFingerprint: string;
  policyVersion: number;
}
interface PreparedAction {
  readonly id: string;
  readonly digest: string;
  readonly action: Readonly<Action>;
  readonly requiresApproval: boolean;
}
interface ExecutionResult {
  readonly value: Json;
  readonly charged: number;
  readonly actionId: string;
}

interface TaskSnapshot extends TaskIdentity {
  sensitive: boolean; // the task family has read private data
  untrusted: boolean; // the task family has read outside content
  calls: number;
  concurrent: number;
  spent: number;
  reserved: number;
}
interface TaskStatus extends TaskSnapshot {
  budget: Readonly<Budget>;
  revoked: boolean; // this task or an ancestor is revoked
}

type PolicyDecision = 'allow' | 'deny' | 'require_approval';
type Policy = (
  action: Readonly<Action>,
  task: Readonly<TaskSnapshot>,
  context?: Readonly<{ signal: AbortSignal }>,
) => PolicyDecision | Promise<PolicyDecision>;

interface GuardOptions {
  policy?: Policy;
  secretValues?: readonly string[];
  clock?: () => number;        // milliseconds; default Date.now
  maxPolicyAttempts?: number;  // 1-16, default 5
  onDecision?: (event: Readonly<GuardDecision>) => void;
  untrustedContextDefault?: UntrustedContextMode; // default 'allow'
  limits?: GuardLimits;
}
interface GuardLimits {
  maxApprovalsPerAction?: number;         // 1-64, default 4
  maxPolicyEvaluations?: number;          // 1-1,024, default 64
  maxPolicyEvaluationsPerFamily?: number; // 1-1,024, default 8
  policyTimeoutMs?: number;               // 100-300,000, default 30,000
  maxJsonBytes?: number;                  // 65,536-67,108,864, default 1,048,576
  maxJsonNodes?: number;                  // 1,000-10,000,000, default 100,000
  maxToolDefinitionBytes?: number;        // 1,024-1,048,576, default 65,536
}
interface GuardDecision {
  operation: 'prepare' | 'approve' | 'execute';
  outcome: 'allowed' | 'denied' | 'succeeded' | 'failed';
  taskId: string;
  tenantId: string;
  principalId: string;
  untrusted: boolean;
  tool?: string;
  actionId?: string;
  resourceId?: string;
  approverId?: string;
  code?: GuardErrorCodeValue; // set when the outcome is denied or failed
}

class GuardError extends Error {
  readonly code: GuardErrorCodeValue;
  readonly detail?: string; // a second, safe uppercase code; see "Errors"
}
function isGuardError(value: unknown): value is GuardError;
const GuardErrorCode: Readonly<Record<GuardErrorCodeValue, GuardErrorCodeValue>>;
const GuardErrorCatalog: Readonly<Record<GuardErrorCodeValue, GuardErrorInfo>>;
interface GuardErrorInfo { meaning: string; retryable: boolean; cause: string }
class InvalidJsonError extends Error {}
function monotonicClock(): number;
```

### Methods

```ts
class AgentGuard {
  constructor(options?: GuardOptions);
  registerTool(definition: ToolDefinition): string;
  approveTool(name: string, fingerprint: string, options?: { reviewedAgainst?: string | null }): void;
  toolChanges(name: string): ToolChanges;
  unapproveTool(name: string): void;
  unregisterTool(name: string): void;
  createTask(options: TaskOptions): TaskHandle;
  delegateTask(parent: TaskHandle, options: Omit<TaskOptions, 'principalId' | 'tenantId'>): TaskHandle;
  revokeTask(task: TaskHandle): void;
  retireTask(task: TaskHandle): void;
  setPolicy(policy: Policy): void;
  prepare(task: TaskHandle, request: { tool: string; args: Json }): Promise<PreparedAction>;
  approve(prepared: PreparedAction, options: { approverId: string; expiresAt: number }): string;
  execute(prepared: PreparedAction, options?: { approvalId?: string }): Promise<Json>;
  executeDetailed(prepared: PreparedAction, options?: { approvalId?: string }): Promise<ExecutionResult>;
  snapshot(task: TaskHandle): Readonly<TaskStatus>;
}
```

| Method | What it does |
| --- | --- |
| `registerTool` | Registers or replaces a tool and returns its fingerprint. The tool cannot be called until it is approved. |
| `approveTool` | Accepts one tool definition by its fingerprint and keeps that definition for later comparison. This is not an approval of any action. |
| `toolChanges` | Compares the current registration with the last approved definition and lists what changed. Read-only. |
| `unapproveTool` | Withdraws that approval. Calls fail with `TOOL_UNAPPROVED` until the tool is approved again. The approved definition is kept. |
| `unregisterTool` | Removes the tool and its approved definition. Prepared actions for it fail with `TOOL_CHANGED`. |
| `createTask` | Creates a task with its own identity, grants and budget, and returns its handle. |
| `delegateTask` | Creates a child task that holds the same or less than its parent. See the [delegation guide](guides/delegation.md). |
| `revokeTask` | Stops a task and its descendants for good. It works even when the clock is failing. |
| `retireTask` | Revokes the task and forgets it, so its ID and memory are freed. A later task may reuse the ID. |
| `setPolicy` | Replaces the policy. Actions prepared under the old policy fail with `POLICY_CHANGED`. |
| `prepare` | Checks one call and returns it as a frozen `PreparedAction`. The handler does not run. |
| `approve` | Records a reviewer's approval of one prepared action and returns an approval ID. |
| `execute` | Repeats every check, consumes the approval if one is needed, and runs the handler once. |
| `executeDetailed` | Same as `execute`, and also returns the charged cost and the action ID. |
| `snapshot` | Returns the task's counters, budget and revocation state. |

Identifiers (tool names, task IDs, tenants, principals, resources, recipients,
approver IDs) are non-empty strings of at most 4,096 characters.

### Tools and grants

- A tool name and a granted resource match exactly. The resource `*` is an
  explicit wildcard; nothing is granted by default.
- A call is allowed only if every task in its ancestry grants the tool and
  resource.
- The fingerprint is a `sha256:` digest of the tool's name, description, schema,
  metadata and flags. Approving it means the host accepts that definition. It
  does not check what `execute` does.
- Registering a tool again withdraws its approval and fails every action already
  prepared for it with `TOOL_CHANGED`, even if the definition is unchanged.
  Register again whenever `parse`, `resolve` or `execute` change.

### What changed in a tool definition

When a tool is registered again, `toolChanges(name)` shows a reviewer what differs
from the definition that was last approved, before they call `approveTool`.

```ts
function diffToolDefinitions(before: unknown, after: unknown): ToolDefinitionDiff;

interface ToolChanges {
  readonly name: string;
  readonly status: 'first_approval' | 'unchanged' | 'changed' | 'unavailable';
  readonly reason?: 'DEFINITION_TOO_LARGE' | 'APPROVED_DEFINITION_TOO_LARGE' | 'APPROVED_DEFINITION_NOT_KEPT';
  readonly fingerprint: string;          // the current registration: what approveTool() takes
  readonly approved: boolean;            // whether the current registration is approved
  readonly approvedFingerprint?: string; // the last approved definition
  readonly definition?: Json;            // the fingerprinted fields now
  readonly approvedDefinition?: Json;    // the fingerprinted fields last approved
  readonly changes: readonly ToolChange[];
  readonly truncated: boolean;           // more than 256 changes; see below for what is always listed
}
interface ToolChange {
  readonly path: string;                 // RFC 6901 JSON Pointer, e.g. /inputSchema/properties/path/type
  readonly kind: 'added' | 'removed' | 'changed';
  readonly before?: Json;                // absent when added
  readonly after?: Json;                 // absent when removed
  readonly hints: readonly ToolChangeHint[];
}
type ToolChangeHint =
  | 'INSTRUCTION_TEXT' | 'HIDDEN_CHARACTERS' | 'SCHEMA_FIELD_ADDED' | 'SCHEMA_LOOSENED' | 'FLAG_LOOSENED';
```

- **What is compared.** The fields the fingerprint covers: `name`, `description`,
  `inputSchema`, `metadata`, `requiresApproval`, `controlPlane`, `maxCost`,
  `parsedArguments` (whether a `parse` function is set) and the outside-content
  labels. Never what `parse`, `resolve` or `execute` do.
- **How.** Objects are compared key by key, so a schema change is reported at its
  own path. Arrays that hold objects (`anyOf`) are compared by index. Arrays of
  plain values (`required`, `enum`) are reported whole. Changes are in path order.
  At most 256 are listed. The guard's own top-level fields (`name`, `description`,
  `requiresApproval`, `controlPlane`, `maxCost`, `parsedArguments` and the
  outside-content labels) are listed even then, so a long schema diff cannot push
  a weakened flag out of the list.
- **Status.** `first_approval`: nothing was approved under this name, or the tool
  was unregistered since. `unchanged`: the registration has the approved
  fingerprint; it still needs `approveTool` after a re-registration. `changed`:
  see `changes`. `unavailable`: the definitions differ but one was too large to
  keep, so there is no diff; `reason` says which, and you compare them yourself.
- **Size.** A definition larger than `limits.maxToolDefinitionBytes` (64 KiB by
  default, measured as compact JSON) still registers and can be approved, as in
  1.0. The guard keeps only its fingerprint and says so with `unavailable`. It
  never shortens a definition silently.
- **Hints are heuristics.** They mark changes that often matter: new text that
  reads like an instruction to a model or names credentials, invisible
  characters, a new schema property, a schema that accepts more than before, a
  guard flag that became weaker (including a raised `maxCost`). They never block anything, they miss things,
  and they give false alarms. An empty `hints` list does not mean a change is
  safe.
- **The values are untrusted.** Descriptions, schemas and metadata are the tool's
  or server's own text. Show them as data: escape them, never render them as
  markup, and never pass them to a model as instructions. The guard's own fields
  (`status`, `kind`, `path` structure, `hints`) are fixed codes; a `path` contains
  key names from the definition.
- **Approve what was read.** Pass the `approvedFingerprint` the reviewer's
  comparison showed as `reviewedAgainst` (`null` for a first approval).
  `approveTool` then fails with `TOOL_CHANGED` if another definition was approved
  in between. The `fingerprint` argument already fails if the tool itself was
  registered again.
- `toolChanges` throws `TOOL_UNKNOWN` for an unregistered name.
  `diffToolDefinitions` compares any two JSON values the same way, for hosts that
  keep their own records; it throws `INVALID_JSON` for a value that is not plain
  JSON within the default limits.

```ts
const fingerprint = guard.registerTool(definition); // the definition changed
const review = guard.toolChanges(definition.name);
if (review.status !== 'unchanged') await showToReviewer(review); // escape every value
guard.approveTool(definition.name, fingerprint, { reviewedAgainst: review.approvedFingerprint ?? null });
```

### Prepare

`prepare` runs these steps in order and stops at the first failure.

1. The task must be live: not revoked, not past its deadline, and the same for
   each ancestor.
2. The request is copied and frozen. It must be `{ tool, args }` and nothing else.
3. The tool must be registered and approved, the task must hold a grant for it,
   and a `controlPlane` tool needs `allowControlPlane`. These checks come before
   any tool callback runs.
4. `parse`, if present, validates and normalizes the arguments. A failure or a
   promise gives `ARGUMENT_INVALID`.
5. `resolve` names the resource, tenant and, for outbound calls, the recipient.
   A failure, a promise or an unknown field gives `RESOLUTION_FAILED`.
6. The built-in checks run: tenant, grant on the resolved resource, recipient,
   sensitive data, configured secrets, outside content and budget.
7. The policy, if any, runs.

`resolve` can be called with a resource the task has no grant for, because the
grant on the resource is checked afterwards. Keep it read-only and scoped to the
task's tenant.

The frozen arguments from step 4 are the ones used for the approval and passed to
the handler. Arguments and results have no prototype: read fields directly and
use `Object.hasOwn(args, 'id')`.

### Policy

A policy is an extra rule from the host. It runs after the built-in checks, on
`prepare` and again on `execute`.

- It can return `deny` or `require_approval`. It cannot allow a call the built-in
  checks refuse.
- If it throws or returns anything else, the call fails with `POLICY_ERROR`.
- Pass `context.signal` to any I/O the policy does. A policy is canceled at the
  task deadline (`TASK_EXPIRED`), after `policyTimeoutMs` (`POLICY_TIMEOUT`), on
  revocation and on `setPolicy`.
- At most `maxPolicyEvaluationsPerFamily` evaluations per task family and
  `maxPolicyEvaluations` per guard run at once. Beyond that the call fails with
  `POLICY_BUSY` and no further callback starts. A policy that ignores
  cancellation keeps its slot until it returns.
- If the task's counters or its sensitive flag change while the policy runs, the
  decision is discarded and the policy runs again on a fresh snapshot. After
  `maxPolicyAttempts` tries the call fails with `POLICY_STATE_CHANGED`. Nothing
  has run and no approval or budget is used.

The guard only compares the snapshot it gave the policy. If the policy reads
other state (a database, another task), the host must coordinate that itself.

### Approval

- An action needs approval when its tool sets `requiresApproval`, when the policy
  returns `require_approval`, or when the outside-content rule below applies.
  `PreparedAction.requiresApproval` reports it.
- `approve` binds to one prepared action: these arguments, this resource, this
  tool registration and this policy version. `expiresAt` must be in the future
  and no later than the deadline of the task and each ancestor
  (`APPROVAL_INVALID` otherwise).
- An action holds at most `maxApprovalsPerAction` live approvals
  (`ACTION_APPROVAL_LIMIT`). Any one of them is enough.
- `execute` consumes the approval immediately before the handler runs. An action
  runs at most once, with or without approval; a second attempt fails with
  `ACTION_USED`.
- An approval never overrides a revoked task, a denial, the sensitive-data rule
  or a failed grant check.

The `approverId` is recorded as given. The host must authenticate the reviewer
before it calls `approve`.

`resourceVersion` is an opaque string from `resolve`. It is part of the approved
action, so the reviewer approves that version. The guard cannot compare it with
the real resource: the handler must do that at the moment it writes. Do not put
secrets or guessable digests of secret content in it.

### Outside content

Outside content is text that people outside your trust boundary can write, such
as email, web pages and customer tickets. In the API the mark is `untrusted`.

| Label | Effect |
| --- | --- |
| `readsUntrusted: true` on a tool | When a call to the tool is dispatched, the whole task family is marked `untrusted` for good. |
| `untrusted: true` from `resolve` | The same, for one call. |
| `untrustedContext: 'require_approval'` | Once the family is marked, every call to this tool needs an approval given after the mark. An earlier approval fails with `APPROVAL_CONTEXT_CHANGED`. |
| `untrustedContext: 'deny'` | Once the family is marked, every call to this tool fails with `UNTRUSTED_CONTEXT_DENIED`, even with an approval. |
| `sendsExternal: false` | A `resolve` that returns `external: true` fails with `RESOLUTION_FAILED` (detail `INVALID_INPUT`). |

Tools without `untrustedContext` use `GuardOptions.untrustedContextDefault`,
which is `allow`. The labels are the host's statement about its tools. The guard
does not inspect content.

### Sensitive data and outbound calls

- An outbound call (`external: true`) needs a `recipient` listed in
  `allowedRecipients` of the task and each ancestor (`RECIPIENT_DENIED`).
- When `resolve` returns `sensitive: true`, the task family is marked sensitive
  as the call is dispatched. From then on every outbound call in that family
  fails with `SENSITIVE_EGRESS_DENIED`. The mark cannot be cleared and an
  approval does not override it.
- For outbound calls the guard searches every key and string in the arguments
  for the literal values in `secretValues`. A match fails with
  `SECRET_EGRESS_DENIED`. Encoded or split values are not found.

### Budgets, cost and deadlines

- Each call counts against the task and each ancestor. `prepare` and `approve`
  check the call count and spent cost. `execute` also checks calls in flight and
  cost reserved by them, so a busy task can still prepare and collect approvals.
- A call counts once it reaches the handler, even if the handler fails. Nothing
  is retried or refunded.
- Before the handler runs, the guard reserves the tool's `maxCost`. Afterwards it
  charges `actualCost`, or `maxCost` when the handler reports none. A report that
  is not a safe integer from 0 to `maxCost` fails with `COST_REPORT_INVALID`,
  charges `maxCost` and revokes the task.
- A handler result that is not plain JSON within the limits fails with
  `RESULT_INVALID`, charges `maxCost` and revokes the task. The effect may
  already have happened.
- The guard's cost is bookkeeping. The host must enforce the real ceiling at the
  provider.
- Deadlines and approval expiries are clock milliseconds. If the clock goes
  backward, time-dependent calls fail with `CLOCK_INVALID` until it catches up;
  `revokeTask` still works. Pass `clock: monotonicClock` to avoid this.
- At the deadline or on revocation the handler's `signal` aborts. The guard
  cannot stop code that ignores the signal. A slot stays in use until the
  handler's promise settles.

### Errors

Every refusal is a `GuardError`. `code` is one of the values in
[the error catalog](errors.md), which also says whether a retry is safe. The same
information is exported as `GuardErrorCatalog`. Error messages never contain
arguments, results or policy output.

Use `isGuardError(error)` rather than `instanceof GuardError`. It also recognizes
errors from a second installed copy of the package.

`detail` is an optional second code:

| `code` | `detail` | Meaning |
| --- | --- | --- |
| `DELEGATION_DENIED` | `GRANT_EXCEEDS_PARENT` | The child asked for a tool or resource an ancestor does not hold. |
| | `RECIPIENT_EXCEEDS_PARENT` | The child listed a recipient an ancestor does not. |
| | `CONTROL_PLANE_EXCEEDS_PARENT` | The child asked for `allowControlPlane` and an ancestor lacks it. |
| | `BUDGET_EXCEEDS_PARENT` | `maxCalls`, `maxConcurrent` or `maxCost` is larger than an ancestor's. |
| | `DEADLINE_EXCEEDS_PARENT` | The deadline is later than an ancestor's. |
| `EXECUTION_ABORTED` | `EFFECT_COMMITTED` | The handler returned, but after the task was revoked or expired. A handler that returns is taken to have performed its effect; the result is withheld. Do not retry. A handler aborted before its effect must throw instead (for example `signal.throwIfAborted()`). |
| `EXECUTION_ABORTED` | none | The handler was canceled and threw. Whether the effect happened is unknown. |
| `RESOLUTION_FAILED`, `ARGUMENT_INVALID`, `TOOL_FAILED` | an adapter code | The safe uppercase `code` of the error the tool callback threw, for example `IDENTITY_DENIED` from the MCP adapter. |

Errors after the handler started (`TOOL_FAILED`, `EXECUTION_ABORTED`,
`RESULT_INVALID`, `COST_REPORT_INVALID`) do not prove that nothing happened.

`InvalidJsonError` is thrown by the JSON helpers in `/internal`. The guard's own
methods report the same problem as a `GuardError` with code `INVALID_JSON`.

### Limits

| Limit | Default | Range | Option |
| --- | --- | --- | --- |
| Size of one JSON value | 1 MiB | 64 KiB to 64 MiB | `limits.maxJsonBytes` |
| Values in one JSON value | 100,000 | 1,000 to 10,000,000 | `limits.maxJsonNodes` |
| Tool definition kept for comparison | 64 KiB | 1 KiB to 1 MiB | `limits.maxToolDefinitionBytes` |
| Changes listed by one comparison | 256 | fixed | |
| JSON nesting | 64 levels | fixed | |
| Live approvals per action | 4 | 1 to 64 | `limits.maxApprovalsPerAction` |
| Policy evaluations at once, per guard | 64 | 1 to 1,024 | `limits.maxPolicyEvaluations` |
| Policy evaluations at once, per task family | 8 | 1 to 1,024 | `limits.maxPolicyEvaluationsPerFamily` |
| Policy run time | 30 s | 100 ms to 300 s | `limits.policyTimeoutMs` |
| Policy re-evaluations per call | 5 | 1 to 16 | `maxPolicyAttempts` |

The JSON limits apply to each value the guard copies: a tool definition, task
options, a `prepare` request, parsed arguments and a handler result. Values must
be plain JSON; cycles, accessors, proxies and class instances are rejected.
Arguments over the limit fail `prepare` with `INVALID_JSON` before any callback
runs.

### Decision events

`onDecision` is called once for every `prepare`, `approve` and `execute` on a known
task, allowed or not. The event holds identifiers and the error code only, never arguments or
results. The hook cannot change the outcome, and an exception it throws is
ignored. See the [audit log guide](guides/audit-log.md).

## MCP adapter: `@shieldaai/agent-guard-mcp`

The adapter registers the tools of a Model Context Protocol (MCP) server with the
guard. It adds no second set of rules: every call still needs a grant, an approved
fingerprint and, where required, an approval. Usage and the supported protocol
features are in the [MCP README](../packages/mcp/README.md).

### Managed connection

```ts
class ManagedMcpConnection {
  static connect(options: ManagedMcpOptions): Promise<ManagedMcpConnection>;
  get status(): 'connecting' | 'refreshing' | 'ready' | 'quarantined' | 'closed';
  get sessionId(): string;
  get revision(): number;
  get inventoryRevision(): number;
  get registrations(): readonly ManagedMcpRegistration[];
  get failureReason(): McpBoundaryErrorCode | undefined;
  get skipped(): readonly McpSkippedOperation[];
  inventory(): McpConnectionInventory; // experimental
  operationChanges(name: string): McpOperationChanges;
  refresh(): Promise<void>;
  close(): Promise<void>;
}
interface ManagedMcpOptions {
  // An AgentGuard or a DurableExecutor. toolChanges is optional; operationChanges() needs it.
  guard: Pick<AgentGuard, 'registerTool'> & Partial<Pick<AgentGuard, 'toolChanges'>>;
  identity: { serverId: string; transportIdentity: string; principalId: string; tenantId: string };
  transport: Transport;                    // owned by the connection from now on
  authorize?: () => void;                  // synchronous; throws to deny
  protectedValues?: readonly string[];
  tools?: readonly McpBinding[];
  resources?: readonly McpResourceBinding[]; // McpBinding plus an exact uri
  prompts?: readonly McpBinding[];
  readsUntrusted?: boolean;                // label every operation on this connection
  limits?: { /* see the table below */ };
}
interface McpBinding {
  name: string;
  resolve(args: Record<string, Json>, task: Readonly<TaskIdentity>): ResolvedAction;
  requiresApproval?: boolean;
  controlPlane?: boolean;
  maxCost?: number;
  measureCost?: (result: Json) => number;
  readsUntrusted?: boolean;
  untrustedContext?: 'allow' | 'require_approval' | 'deny';
  sendsExternal?: boolean;
}
interface ManagedMcpRegistration {
  readonly name: string;        // the name registered with the guard
  readonly fingerprint: string; // pass to approveTool(); new on every connection and refresh
  readonly kind: 'tool' | 'resource' | 'prompt';
  readonly remoteName: string;
  readonly descriptor: Json;
  readonly descriptorDigest: string;
}
interface McpOperationChanges {
  readonly name: string;
  readonly kind: 'tool' | 'resource' | 'prompt';
  readonly remoteName: string;
  readonly status: 'first_approval' | 'unchanged' | 'changed' | 'unavailable';
  readonly reason?: ToolChanges['reason'];
  readonly fingerprint: string;               // pass to approveTool()
  readonly approvedFingerprint?: string;      // pass as reviewedAgainst
  readonly descriptorDigest: string;          // the definition advertised now
  readonly approvedDescriptorDigest?: string; // the definition last approved
  readonly changes: readonly ToolChange[];        // paths into the server's descriptor
  readonly bindingChanges: readonly ToolChange[]; // host flags and identity, e.g. /requiresApproval
  readonly truncated: boolean;
}
interface McpSkippedOperation {
  readonly kind: 'tool' | 'resource' | 'prompt';
  readonly remoteName: string;
  readonly reason: string; // for example SCHEMA_UNSUPPORTED
}
```

- **Only bound operations exist.** The connection registers the tools, resources
  and prompts the host lists, and nothing else the server advertises.
- **`descriptorDigest`** is a `sha256:` digest of the kind, remote name and
  accepted definition. It stays the same while the server advertises the same
  definition. Store it when a person reviews the tool, and approve a
  registration only when its digest matches. The digest does not include the
  server: record it under the server ID and the remote name (for example under
  the registration's `name`), or a review of one server's tool would also
  approve an identically described tool on another server.
- **`fingerprint`** changes on every connection and every `refresh()`, so each
  refresh needs `approveTool` again and invalidates prepared actions.
- **`operationChanges(name)`** compares the definition the server advertises now
  with the one last approved under the same operation name, after a `refresh()`
  or on a new connection to the same server ID. The guard keeps the approved
  definition, so the host does not have to. `changes` lists what the server
  changed, by JSON Pointer into `descriptor`; `bindingChanges` lists what the
  host changed: binding flags and the connection identity (for example
  `/metadata/identity/tenantId`), by path into the guard's definition.
  `unchanged` means the same `descriptorDigest`, flags and identity: the
  session and epoch inside the fingerprint are not reported, and `approveTool` is
  still needed. Hints, limits and the rule that values are untrusted server text
  are those of `toolChanges` above. It throws `INVALID_CONFIGURATION` when the
  `guard` option has no `toolChanges`, and `CONNECTION_UNAVAILABLE` when the name
  is not in the current registry, for example during quarantine. With the
  in-memory guard the approved definition is lost on a process restart; with the
  executor it is in the ledger. `VerifiedMcpHttpSession` has the same method.
- **`skipped`** lists bound operations the server advertised but the adapter
  could not accept, with a reason code. They are never callable.
- **`status`** is `ready` only while operations can be prepared and run. A
  changed tool list, a failed send, an authorization failure, or too many inbound
  messages moves the connection to `quarantined`. Call `refresh()`, review, and
  approve again. A lost transport closes the connection; create a new one.
- **`failureReason`** is the code behind the last quarantine or forced close, for
  example `REGISTRY_CHANGED`, `MESSAGE_BUDGET`, `AUTHORIZATION_DENIED`, or
  `CONNECTION_UNAVAILABLE` when the transport closed or a send failed. A
  successful refresh clears it.
- A failure of one call (timeout, error reply, invalid or oversized result) fails
  only that call with `TOOL_FAILED`. A call cut short because its task was revoked
  or reached its deadline fails with `EXECUTION_ABORTED`. The adapter never retries.
- A closed connection cannot be refreshed. Connect again and review again.

| Limit (`limits`) | Default | Range |
| --- | --- | --- |
| `requestTimeoutMs` | 10,000 | 1 to 120,000 |
| `maxEntries` (bindings, and definitions the server may advertise) | 64 | 1 to 256 |
| `maxMessages` per `messageWindowMs` | 10,000 | 1 to 100,000 |
| `messageWindowMs` | 10,000 | 1 to 600,000 |
| `maxPages` per list request | 4 | 1 to 16 |
| `maxMessageBytes` | 1 MiB | 1 MiB to 16 MiB |

If you raise `maxMessageBytes`, raise the guard's `limits.maxJsonBytes` to at
least the same value. A result the guard refuses fails with `RESULT_INVALID` and
revokes the task. This applies to the in-memory `AgentGuard`. `DurableExecutor`
has no `limits.maxJsonBytes` and accepts results up to a fixed 1 MiB, so leave
`maxMessageBytes` at its default there.

MCP errors are `McpBoundaryError` with a `code`; `McpBoundaryErrorCatalog`
explains each code.

### Verified HTTP session

`VerifiedMcpHttpSession` verifies a JWT access token before it opens a managed
connection to a remote server. The [verified MCP credentials
guide](guides/verified-mcp-credentials.md) shows how to use it.

```ts
class VerifiedMcpHttpSession {
  static connect(options: VerifiedMcpHttpOptions, accessToken: string): Promise<VerifiedMcpHttpSession>;
  get status(): McpConnectionState;
  get sessionId(): string | undefined;
  get registrations(): readonly ManagedMcpRegistration[];
  get skipped(): readonly McpSkippedOperation[];
  get failureReason(): McpBoundaryErrorCode | undefined;
  inventory(): McpConnectionInventory | undefined; // experimental
  refresh(): Promise<void>;
  replaceCredential(accessToken: string): Promise<void>;
  revoke(): Promise<void>;
  close(): Promise<void>;
}
interface VerifiedMcpHttpOptions {
  guard; tools?; resources?; prompts?; limits?; readsUntrusted?; // as in ManagedMcpOptions
  identity: { serverId: string; principalId: string; tenantId: string };
  endpoint: string; // exact HTTPS URL
  authorization: {
    issuer: string;
    jwksUri: string;  // exact HTTPS URL enrolled by the host
    audience: string;
    subject: string;
    requiredScopes?: readonly string[];
    algorithms?: readonly ('RS256' | 'ES256')[];
  };
  fetch: FetchLike; // host-supplied; must enforce TLS and network policy
  verificationTimeoutMs?: number;
  maxJwksBytes?: number;
  maxResponseBytes?: number;
  maxTokenLifetimeSeconds?: number;
}
```

- The session does not log in, fetch tokens or renew them. The host supplies each
  token.
- `replaceCredential` ends the old session first. If the new token fails
  verification, the old one is not restored.
- `revoke` and `close` are final.
- If the server sends back the token in any message, the session closes.

Two smaller helpers are exported for hosts that manage their own connection:
`createRestrictedMcpHttpTransport(options)` (one exact endpoint, no redirects, no
reconnection, bounded responses) and `assertVerifiedMcpClaims(claims, policy,
now?)`, which checks issuer, audience, subject, scopes and expiry on claims the
host has already verified cryptographically.

### Single-tool bridge

```ts
function registerMcpTool(guard: Pick<AgentGuard, 'registerTool'>, registration: McpRegistration): RegisteredMcpTool;
function mcpToolName(serverId: string, toolName: string): string;

interface McpRegistration {
  serverId: string;
  tool: { name: string; description?: string; inputSchema: Json; [key: string]: Json | undefined };
  client: { callTool(request: { name: string; arguments: Record<string, Json> }, options: { signal: AbortSignal }): Promise<Json> };
  resolve(args: Record<string, Json>, task: Readonly<TaskIdentity>): ResolvedAction;
  requiresApproval?: boolean;
  controlPlane?: boolean;
  maxCost?: number;
  measureCost?: (result: Json) => number;
  readsUntrusted?: boolean;
  untrustedContext?: 'allow' | 'require_approval' | 'deny';
  sendsExternal?: boolean;
}
interface RegisteredMcpTool { readonly name: string; readonly fingerprint: string }
```

`registerMcpTool` wraps one tool of an MCP client the host already owns. It
registers the tool without approving it. Every field of the definition is part of
the fingerprint, so call it again when the server's tool list changes; the guard's
`toolChanges(name)` then shows what changed. It does not
watch the connection, validate schemas or restrict the transport; use a managed
connection for that.

## Executor: `@shieldaai/agent-guard-executor`

The executor applies the same rules as the guard and keeps its state in an
encrypted SQLite file, the ledger, so budgets, revocations and used approvals
survive a restart. It gives each task a bearer token, so an agent in another
process can call it over HTTP. One process owns one ledger.

| Import path | Contents | Stability |
| --- | --- | --- |
| `@shieldaai/agent-guard-executor` | `DurableExecutor`, `startExecutorServer`, `ExecutorClient`, `ExecutorError`, tool adapters, `createRestrictedFetch`, model tools | stable |
| `.../sandbox` | Docker sandbox, artifact broker, build provenance | stable |
| `.../pilot` | `verifyPilotReview` | stable |
| `.../ops` | Key ring, key custody, recovery, ledger format | stable |
| `.../inventory` | Inventory observer, host manifest, MCP inventory | experimental |
| `.../internal` | Building blocks for Agent Ops | no compatibility promise |

Operation, key handling and recovery are covered in the
[executor README](../packages/executor/README.md).

### Host API

`DurableExecutor` is an administration object. Keep it in the host and never
expose it to an agent.

```ts
class DurableExecutor {
  constructor(options: ExecutorOptions);
  registerTool(definition: ToolDefinition): string;
  approveTool(name: string, fingerprint: string,
    options?: { reviewedAgainst?: string | null; approverId?: string }): void;
  toolChanges(name: string): ExecutorToolChanges; // ToolChanges plus `approval`
  unapproveTool(name: string): void;
  unregisterTool(name: string): void;
  setPolicy(policy: Policy): void;

  createTask(options: TaskOptions, provenance?: { sensitive?: boolean; sourceTaskId?: string }): TaskCredential;
  delegateTask(parentId: string, options: Omit<TaskOptions, 'principalId' | 'tenantId'>): TaskCredential;
  authenticate(token: string): string; // returns the task ID
  knowsToken(token: string): boolean; // in-memory lookup only; not authentication
  revokeTask(taskId: string): void; // OPERATION_FAILED / REVOCATION_NOT_DURABLE when the ledger write fails
  markSensitive(taskId: string): void;
  snapshot(taskId: string): Readonly<TaskSnapshot>;

  prepare(taskId: string, request: { tool: string; args: Json }): Promise<PreparedAction>;
  preparedAction(actionId: string): Readonly<{
    id: string; taskId: string; digest: string;
    action: Action; requiresApproval: boolean; status: ExecutionStatus;
  }>;
  approve(actionId: string, options: { approverId: string; expiresAt: number }): string;
  recordReviewDecision(actionId: string, decision: 'denied'): void;
  cancel(taskId: string, actionId: string): void;
  execute(taskId: string, actionId: string, options?: { approvalId?: string }): Promise<Json>;
  execution(taskId: string, actionId: string): ExecutionReceipt;
  reconcile(actionId: string, evidence: { outcome: 'SUCCEEDED' | 'FAILED'; actualCost: number; reference: string }): void;

  audit(scope?: { tenantId?: string }): readonly AuditEvent[];
  ledgerFormat(): LedgerFormat;
  close(): void;
  // Memory, task-family maintenance, decision traces and inventory: see below.
}
interface TaskCredential { taskId: string; token: string }
interface ExecutorOptions {
  database: string;          // path of the SQLite file
  encryptionKey: Uint8Array; // exactly 32 random bytes
  rollbackWitness?: { path: string; mode: 'create' | 'resume'; recovery?: 'mirror' };
  clock?: () => number;
  policy?: Policy;
  secretValues?: readonly string[];
  maxPolicyAttempts?: number;                     // 1-16, default 5
  untrustedContextDefault?: UntrustedContextMode; // default 'allow'
  acceptClockSkewMs?: number;                     // one-time override at startup, up to 24 hours
  maxLedgerBytes?: number;                        // 1 MiB-64 MiB, default 16 MiB
  maxRecords?: number;                            // default 10,000
  maxReceiptsPerFamily?: number;                  // 1-4,096, default 64
  maxApprovalsPerAction?: number;                 // 1-64, default 4
  maxRecentEventsPerTenant?: number;              // 16-1,000, default 256
  maxPendingActionsPerFamily?: number;
  maxPendingBytesPerFamily?: number;
  maxTasksPerFamily?: number;
  maxTaskBytesPerFamily?: number;
  decisionTraces?: DecisionTraceOptions;
  inventory?: InventoryOptions;                   // experimental
}
```

Differences from the guard:

- Tasks and actions are named by ID. `createTask` returns the task ID and a
  bearer token; give the agent only the token.
- **Read the action back before a person approves it.** `preparedAction(actionId)`
  returns the stored tool, arguments, resource and recipient from the ledger.
  Show that to the reviewer, not a description supplied by the agent.
- When a reviewer refuses, call `cancel(taskId, actionId)` so the action can never
  run. `recordReviewDecision` only records the refusal.
- `markSensitive` and the `provenance` argument of `createTask` let the host carry
  the sensitive mark, and a link to the task the data came from, into a new task.
- After a restart, budgets, revocations, marks and used approvals are kept. Tool
  approvals and prepared actions are not: register and approve tools again.
- **Approved tool definitions are kept in the ledger.** `approveTool` stores the
  approved definition, the time, the optional `approverId` and the approved
  fingerprint it replaced. After a restart, register the tools and call
  `toolChanges(name)`: a tool whose definition changed while the process was
  down shows `changed` with the diff, and an untouched one shows `unchanged`.
  `toolChanges(name).approval` is `{ approvedAt, approverId?, replacedFingerprint? }`:
  who approved which fingerprint, and which one it replaced, so the pair names
  the comparison the reviewer had. The recent-event list still records only
  `TOOL_APPROVED`, without identifiers.
- The kept definition is bounded by `maxToolDefinitionBytes` (64 KiB by default,
  1 KiB to 1 MiB), and all kept definitions together by an eighth of
  `maxLedgerBytes` (2 MiB with the default 16 MiB), so they cannot crowd out
  tasks and actions. A definition over either bound, or one approved while the
  ledger is at its soft limit, is approved by fingerprint only; `toolChanges` then reports
  `unavailable` with `APPROVED_DEFINITION_NOT_KEPT`. An approval is never refused
  for that reason. `unregisterTool` removes the record, as does reclaiming the
  records of tools a process no longer registers when the tool table is full.
- A ledger written by 1.0.0 holds no approved definitions. Its tools report
  `first_approval` until each is approved once by 1.1.0 or later. The field is
  additive: there is no format step, and a 1.0.0 executor still opens the ledger.
  1.0.0 does not maintain the record, so after running 1.0.0 on the ledger again
  a comparison can be against an approval older than the latest one;
  `approval.approvedAt` shows which.

### Action states and receipts

```text
PREPARED -> RUNNING -> SUCCEEDED | FAILED | UNKNOWN
```

```ts
type ExecutionStatus = 'PREPARED' | 'ADMITTED' | 'RUNNING' | 'SUCCEEDED' | 'FAILED' | 'UNKNOWN';
interface ExecutionReceipt {
  readonly id: string;
  readonly status: ExecutionStatus | 'PRUNED';
  readonly outcome?: 'SUCCEEDED' | 'FAILED'; // only when status is PRUNED, and absent once the stub is dropped
  readonly charged?: number;
  readonly reconciliation?: { readonly referenceHash: string; readonly time: number };
}
```

- The approval, the budget reservation and the move to `RUNNING` are one ledger
  transaction, written before the handler starts. `ADMITTED` stays in the type only
  because ledgers written by the alphas can contain it.
- Whatever a host handler throws, `execute` fails with `TOOL_FAILED` (the handler's
  own safe code in `detail`), or with `EXECUTION_ABORTED` if the call was canceled,
  revoked or past its deadline. The built-in tools keep their own codes.
- If a host handler fails or the process stops after admission, the action is
  `UNKNOWN`. The executor keeps the reservation and never retries. A built-in tool's
  refusal that provably changed nothing settles as `FAILED` at no cost.
- An operator settles an `UNKNOWN` action with `reconcile`, giving the real
  outcome, the real cost and a reference to the evidence. `reconcile` also accepts
  an action left `RUNNING` or `ADMITTED` with no handler in flight. An action can be
  reconciled once.
- A handler that returns after its task was canceled, revoked or expired is
  recorded as `SUCCEEDED` and charged. `execute` fails with `EXECUTION_ABORTED`
  and detail `EFFECT_COMMITTED`.
- After a failed or lost `execute`, read `execution(taskId, actionId)` before
  doing anything else. Starting a new action can repeat the effect.

### HTTP task server

`startExecutorServer({ executor, adminToken, operatorId, ... })` listens on
`127.0.0.1` and returns `{ server, url, close }`. Every route is a `POST` with a
JSON object body and `Authorization: Bearer <token>`. Requests from a browser
(with an `Origin` header) are refused.

Task routes take a task's token. The task is always the token's task.

| Route | Body | Response |
| --- | --- | --- |
| `/v1/task/prepare` | `{ tool, args }` | the `PreparedAction` |
| `/v1/task/execute` | `{ actionId, approvalId? }` | `{ value }` |
| `/v1/task/snapshot` | `{}` | the `TaskSnapshot` |
| `/v1/task/execution` | `{ actionId }` | the `ExecutionReceipt` |
| `/v1/task/cancel` | `{ actionId }` | `{ cancellationRequested: true }` |
| `/v1/task/delegate` | `{ options }` (`id`, `grants`, `budget`, `allowedRecipients?`, `allowControlPlane?`) | the child's `{ taskId, token }` |

Administration routes take the `adminToken`.

| Route | Body | Response |
| --- | --- | --- |
| `/v1/admin/create-task` | `{ options, provenance? }` | `{ taskId, token }` |
| `/v1/admin/action` | `{ actionId }` | the stored action, as `preparedAction()` |
| `/v1/admin/approve` | `{ actionId, expiresAt }` | `{ approvalId }` |
| `/v1/admin/revoke` | `{ taskId }` | `{ revoked: true }` |
| `/v1/admin/reconcile` | `{ actionId, outcome, actualCost, reference }` | `{ reconciled: true }` |
| `/v1/admin/audit` | `{}` | recent events |

The approver recorded by `/v1/admin/approve` is the server's `operatorId`. It
cannot be set in the request.

An error response is `{ "error": CODE, "retryable": boolean }`. `retryable` is
true only when sending the same request again later cannot repeat an effect.

One response adds a `detail`. When `/v1/admin/revoke` could not record the
revocation in the ledger, it answers 503 with `"error": "OPERATION_FAILED"`,
`"retryable": true` and `"detail": "REVOCATION_NOT_DURABLE"`. The task is denied
in the running process, and the executor records the revocation with its next
successful ledger write or when it closes. Repeat the request until it succeeds:
if the process exits before any ledger write succeeds, the revocation is lost and
the task is valid again after a restart.

| Status | Meaning | Examples |
| --- | --- | --- |
| 400 | Malformed request | `REQUEST_INVALID`, `REQUEST_TOO_LARGE`, `REQUEST_TIMEOUT`, `INVALID_INPUT`, `ARGUMENT_INVALID` |
| 401 | Missing or wrong token | `UNAUTHENTICATED` |
| 403 | Not allowed | `GRANT_DENIED`, `APPROVAL_REQUIRED`, `TASK_REVOKED`, `CALL_BUDGET_EXCEEDED`, `REQUEST_DENIED` |
| 404 | Unknown action, task or tool | `INVALID_PREPARED`, `INVALID_TASK`, `TOOL_UNKNOWN` |
| 409 | State changed or already used | `ACTION_USED`, `POLICY_CHANGED`, `TOOL_CHANGED`, `APPROVAL_CONTEXT_CHANGED` |
| 429 | Over a capacity limit | `REQUEST_RATE_LIMITED`, `CONCURRENCY_EXCEEDED`, `POLICY_BUSY`, `CAPACITY_EXCEEDED` |
| 503 | Store, policy or tool failure | `TOOL_FAILED`, `EXECUTION_ABORTED`, `POLICY_ERROR`, `CLOCK_INVALID`, `OPERATION_FAILED` |

The status of every guard code is in the [error catalog](errors.md).

| Server limit | Default | Option |
| --- | --- | --- |
| Request body | 256 KiB | `maxRequestBytes` |
| Request time | 10 s | `requestTimeoutMs` |
| Open connections | 64 | `maxConnections` (1 to 4,096) |
| Requests in flight | 32, of which an eighth (at least 1) is kept for admin routes | `maxActiveRequests` (1 to 1,024) |
| Requests per minute per token | 600; an unknown token is refused before it is counted | `requestsPerMinutePerCredential` |
| Requests per minute, all task tokens | 6,000; only authenticated task requests count, admin routes do not | `requestsPerMinute` |

Every limit is checked before the ledger is read, so a token over its limit costs
no ledger read.

`ExecutorClient` is the matching client for an agent process. It has task
operations only: `prepare(tool, args)`, `execute(actionId, { approvalId? })`,
`snapshot()` and `execution(actionId)`. Its errors carry the same `code` and
`retryable`.

### Governed memory

Memory entries are stored in the ledger and read and written through two
ordinary tools, so grants, tenants and approvals apply to them.

```ts
importMemory(entry: {
  id: string; tenantId: string; origin: string; value: Json;
  sensitive?: boolean; trusted?: boolean; untrusted?: boolean;
}): void;
registerMemoryTools(prefix?: string): Readonly<{ read: string; write: string }>;
quarantineMemory(tenantId: string, entryId: string): void;
rollbackMemory(tenantId: string, entryId: string, version: number): void;
```

`registerMemoryTools()` registers `memory.read` and `memory.write` (or another
prefix) and returns their fingerprints for `approveTool`. Grants name entry IDs.
Each lookup uses the task's own tenant, so the same ID in two tenants is two
entries.

| Tool | Arguments | Result |
| --- | --- | --- |
| `memory.read` | `{ id }` | `{ id, tenantId, origin, value, version, sensitive, trusted, parentIds, quarantined: false, familyId? }` |
| `memory.write` | `{ id, value, ifVersion }` | `{ id, version, sensitive, trusted: false }` |

- **Versions.** Use `ifVersion: 0` to create an entry and the current version to
  replace it. The version is checked at `prepare` (`RESOLUTION_FAILED`) and again
  at `execute` (`MEMORY_VERSION_CHANGED`).
- **Sensitivity.** An import is sensitive unless the host says otherwise, and an
  entry's sensitivity is never lowered. A write by a sensitive task family is
  sensitive.
- **Outside content.** An entry written by a family that had read outside
  content, or imported with `untrusted: true`, carries the `untrusted` mark.
  Reading it marks the reader's family.
- **`trusted`** is a label for the host's own use. It grants nothing. Writes by
  tools are never trusted.
- **Quarantine** makes every version of an entry, and the entries derived from
  it, unavailable in that tenant (`MEMORY_UNAVAILABLE`). It survives a restart
  and cannot be undone by rollback.
- **Rollback** adds a new version with the value of an old one. History is kept.

| Memory limit | Value | Error |
| --- | --- | --- |
| One value | 64 KiB of JSON | `MEMORY_LIMIT` |
| Versions per entry | 128 | `MEMORY_LIMIT` |
| Writes per task family | 256 | `FAMILY_MEMORY_LIMIT` |
| Stored bytes per task family | 512 KiB | `FAMILY_MEMORY_LIMIT` |

### Audit events, decision traces and retention

`audit({ tenantId? })` returns recent events, oldest first:

```ts
interface AuditEvent {
  time: number;
  event: string;
  sequence?: number; // strictly increasing
  tenantId?: string;
  taskId?: string;
  actionId?: string;
}
```

It is a window, not a full history. To keep everything, poll it, store the events
elsewhere and treat a gap in `sequence` as lost events. Decision traces
(`decisionTraces`, `decisionTraceSnapshot`, `exportDecisionTraces`) are a second,
optional stream without raw identifiers; see the
[decision traces guide](guides/decision-traces.md). The
[audit log guide](guides/audit-log.md) compares the options.

| Kept | Limit | What happens at the limit |
| --- | --- | --- |
| Audit events per tenant | `maxRecentEventsPerTenant`, default 256 | The oldest are dropped. |
| Audit events in total | 1,000 | The busiest tenant is trimmed first. |
| Settled receipts per task family | `maxReceiptsPerFamily`, default 64 | The oldest become `PRUNED` stubs that keep `outcome` and `charged`. |
| Settled receipts per tenant | 256, or `maxReceiptsPerFamily` if that is larger | The same. |
| `PRUNED` stubs | 256 per family, 1,024 per tenant, 4,096 per ledger at the default ledger size | The oldest are dropped; `execution()` then returns `status: 'PRUNED'` without `outcome` or `charged` while the action's settlement event is still in the audit window, and fails with `INVALID_PREPARED` after that. |
| Ledger size (decoded) | `maxLedgerBytes`, default 16 MiB | Calls that add state fail with `STORE_CAPACITY_EXCEEDED` (`detail: 'SOFT_LIMIT'`) once the ledger would pass `maxLedgerBytes` minus a reserve of one eighth, at most 1 MiB. Revoke, cancel, settlement and `reconcile` use the reserve; if that is full too, they drop the oldest half of the audit events. Receipts, budgets and reservations are never deleted. |

A tenant's traffic removes only that tenant's oldest entries. When a
ledger-wide limit is reached, the tenant holding the most loses its oldest. The one
exception is the full reserve described above, which drops audit events of every
tenant.

A `PRUNED` receipt is a settled result. It never means the outcome is unknown and
never permits a retry. Budgets and unresolved reservations are always kept.

### Task-family retirement and archival

These host-only methods free ledger space for finished work. They have no HTTP
routes. Authenticate the operator and choose the tenant before calling them.

```ts
previewTaskFamilyRetirement(scope: { tenantId: string; taskId: string }): TaskFamilyRetirementPreview;
retireTaskFamily(scope: { tenantId: string; taskId: string; expectedDigest: string }): TaskFamilyRetirementResult;
archiveTaskFamily(scope: { tenantId: string; taskId: string; expectedDigest: string }): TaskFamilyArchiveReceipt;
verifyTaskFamilyArchive(scope: { tenantId: string; archiveId: string }): TaskFamilyArchiveReceipt;
findTaskFamilyArchive(scope: { tenantId: string; taskId: string }): TaskFamilyArchiveReceipt | null;
listExecutions(scope: { tenantId: string; statuses?: readonly ExecutionStatus[]; limit?: number; cursor?: string }): ExecutionList;
maintenanceStatistics(scope: { tenantId: string }): MaintenanceStatistics;
```

1. **Preview.** Pass any task of the family. The preview covers the whole family
   and returns counts, `retirementBlockers`, `archiveBlockers` and a
   `reviewDigest`. It contains no arguments, memory values or keys.
2. **Retire.** Pass the digest back as `expectedDigest`. Any ledger write or
   restart since the preview fails with `LIFECYCLE_PREVIEW_STALE`. Retirement
   revokes every task, cancels prepared actions and quarantines the family's
   memory. It refuses while work is admitted, running or `UNKNOWN`
   (`FAMILY_UNRESOLVED_WORK`, `FAMILY_ACTIVE_WORK`); reconcile first.
3. **Archive.** Preview again, then archive. The family's records move into one
   encrypted archive inside the ledger and leave the live state. A family that is
   not retired fails with `FAMILY_NOT_RETIRED`. A family whose memory or tasks
   are referenced by another family fails with `FAMILY_EXTERNAL_REFERENCE`.
4. **Verify.** `verifyTaskFamilyArchive` decrypts and checks the archive and
   returns its receipt. `findTaskFamilyArchive` finds the receipt from any task
   ID of the family, which lets the host recover if it crashed before saving it.

An archived task ID can never be used again in that ledger (`DUPLICATE_TASK`),
and an archived memory ID cannot be recreated in its tenant. Old tokens stay
invalid. Archiving frees live capacity; it does not erase data.

| Archive limit | Value |
| --- | --- |
| Archives per ledger | 4,096 |
| Archived task and memory IDs | 65,536 |
| Archive ciphertext in total | 256 MiB |
| One archive, decoded | 16 MiB |

Nothing is evicted at these limits. Further archives fail with
`ARCHIVE_CAPACITY_EXCEEDED`, `STORE_ARCHIVE_CAPACITY` or
`STORE_CAPACITY_EXCEEDED`, and live state is left alone. To move finished
single-task families out of the ledger into files you own, see the
[company history guide](guides/company-history.md).

`listExecutions` returns `UNKNOWN` actions by default, 25 per page and at most
100, without arguments or results. If the ledger changes between pages the cursor
fails with `LIFECYCLE_CURSOR_STALE`; start again from the first page.

### Inventory (experimental)

`@shieldaai/agent-guard-executor/inventory` exports a read-only description of
the tasks, tools and grants in a ledger, for [Agent Map](#agent-map-shieldaaiagent-map).
It can change in a minor release.

| Export | Purpose |
| --- | --- |
| `executor.inventorySnapshot({ tenantId })` | One tenant's tasks, grants and tools. Needs the `inventory` constructor option. |
| `startInventoryServer`, `createInventoryObserverToken` | A separate loopback listener with one route, `POST /v1/inventory/snapshot`, and its own tokens. |
| `validateInventoryManifest`, `loadInventoryManifestFile`, `composeInventorySnapshot` | Add a host manifest: the agents, owners and deployments a person declared. |
| `validateMcpConnectionInventory`, `validateMcpInventorySources`, `composeMcpInventorySnapshot` | Add observations from `ManagedMcpConnection.inventory()`. |

A snapshot is complete or it fails; it is never truncated. Reading it runs no
policy or tool callback and changes no ledger state. Errors use `INVENTORY_*`
codes and contain no source values.

The file formats are described in
[Inventory formats](agent-cartography-contract.md). Options, limits and the
observer's HTTP behavior are in the
[executor README](../packages/executor/README.md).

## Scenarios: `@shieldaai/agent-guard-scenarios`

```ts
function runConformance(options?: ConformanceOptions): Promise<ConformanceReport>;
const scenarioCatalog: readonly ScenarioDefinition[];
const SCENARIO_CATALOG_VERSION: '1.4.0';

interface ConformanceOptions {
  scenarioIds?: readonly ScenarioId[]; // 'S01' to 'S13'; default all
  caseTimeoutMs?: number;              // per case; default 5,000
  createGuard?: (options: GuardOptions) => GuardLike; // default: new AgentGuard(options)
}
interface ConformanceReport {
  catalogVersion: string;
  passed: boolean;
  scenarioCount: number;
  caseCount: number;
  passedCases: number;
  failedCases: number;
  results: readonly ConformanceCaseResult[];
}
interface ConformanceCaseResult {
  scenarioId: ScenarioId;
  variant: 'malicious' | 'benign'; // the hostile case and the ordinary case
  passed: boolean;
  assertions: number;
  handlerInvocations: number;
  denialCodes: readonly string[];
  failure?: string;
}
```

`GuardLike` is the subset of `AgentGuard` the scenarios call: `registerTool`,
`approveTool`, `createTask`, `delegateTask`, `revokeTask`, `setPolicy`, `prepare`,
`approve`, `execute` and `snapshot`, plus an optional `toolChanges`. An adapter
that has `toolChanges` also runs the definition-diff checks of S06. The catalog has its own version, so compare
two reports by `catalogVersion`. [Scenarios](scenarios.md) describes each case and
how to run them against your own integration.

## Agent Map: `@shieldaai/agent-map`

Agent Map is an experimental, read-only service that answers questions about an
inventory of agents: which agents exist, what they can reach and what changed. It
reads inventory that the Cartography collector has loaded into Neo4j. It never
authorizes or runs a call, and it is outside the compatibility promise.

Its HTTP and MCP operations, configuration and limits are documented in the
[Agent Map README](../packages/agent-map/README.md). To set up the whole
pipeline, follow the [agent cartography guide](guides/agent-cartography.md).
