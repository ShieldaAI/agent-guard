# Alpha API contract

The host owns `AgentGuard`. Give the model only a dispatcher, never administration methods or opaque handles. Authority is stored by object identity inside one guard instance. All state is in memory and lasts for that instance's lifetime.

Exports from `@shieldaai/agent-guard`:

```ts
type Json = null | boolean | number | string | readonly Json[] | { readonly [key: string]: Json };
interface Capability { tool: string; resources: readonly string[] }
interface Budget { maxCalls: number; maxConcurrent: number; maxCost: number; deadline: number }
interface TaskOptions {
  id: string; principalId: string; tenantId: string;
  grants: readonly Capability[]; budget: Budget;
  allowedRecipients?: readonly string[];
  allowControlPlane?: boolean;
}
interface TaskIdentity { id: string; principalId: string; tenantId: string }
interface TaskHandle { readonly id: string }
interface ResolvedAction {
  resourceId: string; tenantId: string;
  external?: boolean; recipient?: string; sensitive?: boolean;
}
interface ToolDefinition {
  name: string; description: string; inputSchema?: Json; metadata?: Json;
  requiresApproval?: boolean; controlPlane?: boolean;
  // Nonnegative safe integer cost units; the adapter enforces its provider-side bound.
  maxCost?: number;
  resolve(args: Json, task: Readonly<TaskIdentity>): ResolvedAction;
  execute(args: Json, context: {
    signal: AbortSignal; action: Readonly<Action>; task: Readonly<TaskIdentity>
  }): Promise<ToolResult> | ToolResult;
}
interface ToolResult { value: Json; actualCost?: number }
interface Action extends ResolvedAction {
  tool: string; args: Json; toolFingerprint: string; policyVersion: number;
}
interface TaskSnapshot extends TaskIdentity {
  sensitive: boolean; calls: number; concurrent: number; spent: number; reserved: number;
}
type PolicyDecision = 'allow' | 'deny' | 'require_approval';
type Policy = (action: Readonly<Action>, task: Readonly<TaskSnapshot>) => PolicyDecision | Promise<PolicyDecision>;
interface GuardOptions { policy?: Policy; secretValues?: readonly string[]; clock?: () => number }
interface PreparedAction {
  readonly id: string; readonly digest: string;
  readonly action: Readonly<Action>; readonly requiresApproval: boolean;
}
class GuardError extends Error { readonly code: string }
class AgentGuard {
  constructor(options?: GuardOptions);
  registerTool(tool: ToolDefinition): string; // Returns the fingerprint. Approval is a separate step.
  approveTool(name: string, fingerprint: string): void;
  createTask(options: TaskOptions): TaskHandle;
  delegateTask(parent: TaskHandle, options: Omit<TaskOptions, 'principalId' | 'tenantId'>): TaskHandle;
  revokeTask(task: TaskHandle): void;
  setPolicy(policy: Policy): void; // Invalidates existing prepared actions and approvals.
  prepare(task: TaskHandle, request: { tool: string; args: Json }): Promise<PreparedAction>;
  approve(prepared: PreparedAction, options: { approverId: string; expiresAt: number }): string;
  execute(prepared: PreparedAction, options?: { approvalId?: string }): Promise<Json>;
  snapshot(task: TaskHandle): Readonly<TaskSnapshot>;
}
```

## Execution rules

### Grants and tool registration

Tool names and resource grants match exactly. The resource `*` is an explicit wildcard. Every grant in the task's ancestry must allow an operation. Child tasks inherit their principal and tenant; their grants, recipients, control-plane authority and budgets cannot exceed the parent's limits. Task IDs must be unique within a guard instance.

The host must approve tool metadata before preparing or executing a call. Fingerprints cover the description, schema and security configuration. Re-registering a tool invalidates its existing prepared actions, even if the metadata is unchanged. Approving metadata does not verify the implementation's safety.

### Prepared actions and policy

The guard accepts finite, plain JSON values, then clones and freezes them. It rejects cycles, accessors, exotic objects and inputs that exceed the size or depth limits below. It also validates and stores the resolver's result. Changing caller-owned arguments cannot change the stored invocation.

Both preparation and execution apply the mandatory checks. Custom policy may add restrictions; it cannot relax them. If policy throws or returns an invalid decision, the call is denied. Without a custom policy, an action is allowed only if every mandatory check passes.

After awaiting policy, the guard rechecks the policy version, grants, revocation, tool approval, tenant, sensitivity and deadline. If a counter or shared sensitivity value in the supplied task snapshot has changed, it rejects with `POLICY_STATE_CHANGED`. This rejection starts no handler and consumes no approval or budget, so the host may retry with a fresh evaluation. The snapshot check, final reservations, approval consumption and handler invocation run without an intervening asynchronous pause.

This check covers the supplied local snapshot. It cannot coordinate external mutable state or other tasks that a custom policy reads through a closure. Grants cannot be changed in place, administration APIs must remain with the trusted host, and the core does not require a remote policy service.

### Approval and dispatch

Each prepared action can run at most once. A required approval is bound to that action and its policy and tool revisions. It must expire no later than the task deadline and is consumed immediately before dispatch. Only trusted host code may approve actions or tool metadata.

### Sensitive data and outbound calls

Outbound tools require an explicitly allowed recipient. Parent and descendant tasks share a sensitive flag. Once a trusted resolver marks the context sensitive, external sends are denied. The flag is set before dispatch and cannot be cleared.

The guard scans each outbound string value for configured literal secrets or canaries and omits argument values from errors. The scanner does not cover arbitrary encodings or secrets split across values.

### Budgets and cancellation

Before dispatch, budget admission updates every ancestor synchronously. Calls count attempts that reach a handler. A failed call or an uncertain side effect is not automatically retried or refunded.

Budget `maxCost`, tool `maxCost` and reported `actualCost` use nonnegative safe integers in the same unit chosen by the host, such as microcurrency units. Fractional values and unsafe integers are rejected. The guard reserves `maxCost` and then settles the charge using `actualCost`, which must not exceed the reservation. If usage is omitted, it charges `maxCost`. An invalid or excessive cost report fails the call and revokes the task, charging the full reservation. The host must enforce the provider's actual cost ceiling.

Concurrency stays reserved until the registered handler's promise settles, including after cancellation. Revocation or a task or ancestor deadline signals cancellation through `AbortSignal`; it cannot forcibly stop arbitrary code. The guard also checks the clock when a result settles, so a handler that blocks the timer cannot return a successful result after its deadline. There is no hard process timeout.

An MCP client may settle its request before the remote server stops working. Local accounting therefore cannot bound the remaining remote work. An error after invocation does not prove that no side effect occurred.

## Packages

- `@shieldaai/agent-guard`: core above.
- `@shieldaai/agent-guard-mcp`: thin registered-tool adapter for a host-supplied MCP client, without a separate policy engine or automatic metadata approval.
- `@shieldaai/agent-guard-scenarios`: versioned scenario catalog plus executable conformance checks over the public core API. Synthetic effects only.

The trusted resolver runs during preparation. Execution checks its bound resource and tenant context; it does not query changing ownership again. A handler/resource service must revalidate mutable ownership or resource versions before performing an effect.

Each normalized JSON value is limited to 1 MiB of canonical UTF-8 JSON, 100,000 nodes and 64 levels of depth. Bytes are counted during traversal, including escaped strings, keys and punctuation, so oversized inputs are rejected before constructing their complete serialization. The limit applies to complete request/result envelopes, metadata and other normalized structures, including the prepared-action digest envelope. Leave room for enclosing fields when sizing payloads. A malformed or oversized handler result produces `RESULT_INVALID`, charges the declared maximum and revokes that task; the operation may already have performed an effect.
