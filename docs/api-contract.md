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
  registerTool(tool: ToolDefinition): string; // returns current fingerprint; does NOT approve
  approveTool(name: string, fingerprint: string): void;
  createTask(options: TaskOptions): TaskHandle;
  delegateTask(parent: TaskHandle, options: Omit<TaskOptions, 'principalId' | 'tenantId'>): TaskHandle;
  revokeTask(task: TaskHandle): void;
  setPolicy(policy: Policy): void; // increments revision, invalidates prepared actions/approvals
  prepare(task: TaskHandle, request: { tool: string; args: Json }): Promise<PreparedAction>;
  approve(prepared: PreparedAction, options: { approverId: string; expiresAt: number }): string;
  execute(prepared: PreparedAction, options?: { approvalId?: string }): Promise<Json>;
  snapshot(task: TaskHandle): Readonly<TaskSnapshot>;
}
```

Rules:

- Tool and resource grants are exact matches; resource `*` is an explicit wildcard. Tools are exact names. All grant layers must allow the operation. Child grants cannot widen any ancestor, tenant/principal remain inherited, and child recipients/control-plane authority/budgets cannot widen the parent's bounds. IDs are unique for a guard lifetime.
- Tool metadata must be explicitly approved before preparation/execution. Canonical fingerprints cover description, schema and security configuration. Re-registering code invalidates existing prepared actions even if metadata is identical. Metadata approval is not proof of safe tool implementation.
- Normalize only finite plain JSON, clone and freeze it, reject cycles/accessors/exotic objects or excessive input depth/size. No mutations of caller-owned input can alter a prepared invocation. Resolver outputs are validated and bound. The executor uses that stored immutable invocation.
- Preparation and execution both check mandatory gates. Async custom policy can only tighten them. Invalid policy results/exceptions deny. After the policy awaits, recheck current version, grants/revocation, tool approval, tenant, sensitivity and deadline before dispatch. Reject with `POLICY_STATE_CHANGED` if any counter or shared sensitivity in the supplied task snapshot changed during evaluation; no asynchronous gap follows the snapshot check, final reservations/approval consumption and handler invocation. This rejection starts no handler and consumes no approval or budget, so the host may retry through a fresh evaluation. This check does not coordinate external state or other tasks that a custom policy reads through a closure.
- Each prepared action dispatches at most once. Required approval must bind that prepared action, policy/tool revision, expire before or at task deadline, and be consumed once immediately before dispatch. Approval and metadata administration are trusted-host APIs.
- Outbound tools require a declared allowed recipient. A shared sensitive flag is monotonic across parent/descendant tasks; once set, external sends deny. Trusted resolver sets sensitivity before dispatch conservatively. Scan every outbound string leaf for configured literal secrets/canaries; never put argument values in error messages. Encoded/chunked exfiltration is outside this alpha scanner's guarantee.
- Budget admission updates every ancestor synchronously before dispatch. Calls count attempts that reached a handler; failed/unknown effects are not automatically retried/refunded. Budget maxCost, tool maxCost and actualCost are nonnegative safe integers in the same host-defined unit (for example, microcurrency units); floating point amounts and unsafe integers are rejected. Reserve maxCost, then reconcile actualCost <= maxCost. If omitted, charge maxCost. Invalid/overrun reports fail and revoke the task while retaining reservation as spent. The host must enforce the actual provider upper bound.
- Hold concurrency until the registered handler's promise settles even if canceled. AbortSignal requests cancellation at task/ancestor deadline or revocation; it cannot kill arbitrary code. An MCP client can settle its request before a remote server stops, so this local accounting does not bound remaining remote work. Do not claim a hard OS timeout. Errors after invocation do not imply no side effect happened.
- Default no custom policy permits only actions that pass every mandatory gate. No untrusted policy changes, auto-approved new tools, remote service requirement, mutable grants or exposed authority stores.

Packages:

- `@shieldaai/agent-guard`: core above.
- `@shieldaai/agent-guard-mcp`: thin registered-tool adapter for a host-supplied MCP client, without a separate policy engine or automatic metadata approval.
- `@shieldaai/agent-guard-scenarios`: versioned scenario catalog plus executable conformance checks over the public core API. Synthetic effects only.

The trusted resolver runs during preparation. Execution checks its bound resource and tenant context; it does not query changing ownership again. A handler/resource service must revalidate mutable ownership or resource versions before performing an effect.

Each normalized JSON value is limited to 1 MiB of canonical UTF-8 JSON, 100,000 nodes and 64 levels of depth. The limit applies to complete request/result envelopes, metadata and other normalized structures, including the prepared-action digest envelope. Budget headroom for enclosing fields, not just the raw payload. A malformed or oversized handler result produces `RESULT_INVALID`, charges the declared maximum and revokes that task; the operation may already have performed an effect.
