# Threat model

Agent Guard is an authorization layer for tools called by an agent. The `@shieldaai/agent-guard` TypeScript alpha runs inside the application that registers and executes those tools. It can stop a mediated call before the registered handler starts. It does not isolate the handler, the model, or the application from the operating system. `@shieldaai/agent-guard-mcp` adapts a host-supplied MCP client to the same executor; it is not a second policy engine.

The security claim is deliberately narrow: given a trusted host, correct tool definitions and trusted task context, the executor applies the configured grants and checks to calls made through it. The [scenario specification](scenarios.md) describes the intended acceptance cases and their limits. Neither the word “firewall” nor a passing test corpus means that all prompt injection or privilege escalation is prevented.

## Protected boundary

```text
Untrusted model output / retrieved content / caller arguments
                         |
                         v
                 Trusted host adapter
       establishes task and caller context; validates inputs
                         |
                         v
                Registered-tool executor
        grants -> policy -> approval -> budget reservation
                         |
                         v
                  Trusted tool handler
            performs the authorized operation only
```

The application must route the relevant operations through the executor. A model that can also invoke an unguarded shell, SDK client, database connection, network client or raw MCP transport can bypass this boundary.

An MCP wrapper mediates the calls made through that wrapper. It does not provide a network firewall, sandbox a server, or prevent a client from using another connection. A remote server remains responsible for enforcing its own resource authorization and for acting consistently with the tool contract.

## Trusted components

The alpha trusts:

- The application host and the code that creates task handles, grants and parent relationships.
- Tool registration, argument validation and the code that derives canonical resources, recipients and tenants from validated arguments.
- Registered tool handlers and their credential custody. A permitted handler must not perform unrelated operations.
- The host's approval interface, policy configuration, clock and process memory.
- Host-supplied sensitivity and task attribution. Sensitive access must be marked before the relevant data can affect another action.
- The integration that sends all protected operations through the executor, including any MCP transport wrapper.

A task handle identifies context established by the host. It is not a general identity provider, an OAuth token, or proof of identity across machines. The guard recognizes issued handles by object identity; an object with the same printed ID does not carry the same authority. Do not accept a task handle, tenant, parent or administrator role from model-generated JSON as authenticated authority. Do not expose host administration functions as ordinary agent tools. The host also authenticates reviewers: an `approverId` supplied to the approval API is not itself proof of a human decision or a second person's identity.

## Untrusted inputs

Assume the model may follow hostile instructions. Model-generated arguments, user text, documents, search results, tool results, tool descriptions and agent messages may contain attempts to:

- Invoke an unregistered tool or access an unauthorized resource.
- Claim a different tenant, parent, task or administrator identity.
- Widen a child task's permissions.
- Change policy, grant approval or obtain credentials.
- Send sensitive data to an unauthorized recipient, including on a familiar domain.
- Replay or alter an approved action.
- Use changed MCP tool metadata without review.
- Exhaust call or concurrency limits, or keep a task running indefinitely.

These inputs do not become trusted because they are valid JSON, match a tool schema, come from an allowed domain or were produced by another agent.

## How the alpha limits those actions

Tool grants and resource checks are explicit. Tool names and descriptions cannot grant authority. Tool names and resources match exactly; resource `*` is an explicit wildcard grant. Resource matching must use the application's canonical identifiers; a free-text name is insufficient when it can alias a different tenant, account, file or destination. Registered metadata needs host approval, and custom policy can only tighten the mandatory checks.

Child tasks receive authority from trusted host code. The intersection of the applicable grants must constrain delegated work. A caller-provided parent name is not a delegation chain. This alpha's delegation boundary is local to one executor and its shared context.

An approval authorizes the specific action presented to the reviewer. The prepared invocation stores cloned, immutable JSON arguments and resolved action context. Arguments, resources, task context and applicable policy must remain consistent with that approval. Consumption must be single-use and must check expiry before dispatch. A policy change invalidates existing prepared actions and approvals. Approval does not override a revoked task, an explicit denial, sensitive-context restrictions or a failed resource check.

A custom policy's supplied task snapshot must still match the current local counters and shared sensitivity immediately before preparation completes or execution dispatches. Concurrent changes cause `POLICY_STATE_CHANGED` without consuming the action, approval or budget. Policies that consult external mutable data or other task snapshots need host-side coordination; the guard cannot make those reads atomic with a remote effect.

Budgets constrain admission to the registered executor and its task ancestors. Local reservations and approval consumption can be atomic within one process when they are made together before dispatch. Calls that reach a handler count even when the handler fails. Concurrency remains reserved until the handler settles. The executor reserves the trusted tool's declared maximum cost and reconciles its reported actual cost; the host must enforce that maximum at the provider. That is not a transaction with a remote service: a crash, timeout or lost response can leave the outcome of a side effect unknown. Retrying an operation requires the handler's idempotency or reconciliation mechanism.

The alpha maintains a monotonic sensitive flag shared across related parent/descendant tasks. Once marked sensitive by a trusted resolver, that context cannot perform external sends, including with approval. External actions also require an explicitly allowed recipient. Configured literal secrets are scanned in outbound string leaves. These checks do not automatically discover every secret or track every transformation of a value. A separate new root task must not be used to erase the labels of copied data; the host must carry the relevant context across reuse outside an existing task family.

## Limits that affect deployment

| Limit | Consequence |
|---|---|
| In-process execution | Compromised host code, an untrusted dependency or arbitrary JavaScript execution can alter or bypass the guard. |
| Trusted handlers | Once allowed, a handler can use the authority available to that process. The guard cannot inspect every internal API call or socket. |
| Local memory | Task state, approvals, revocation and counters are not durable or shared across processes. Restarting or creating another executor is not continuity of the same security state. |
| No distributed transaction | Approval consumption, budget reservation and an external side effect cannot be committed as one operation by this library. |
| Cooperative cancellation | A deadline or abort signal cannot forcibly stop a handler that ignores it or retract a request already accepted by a remote service. |
| Explicit context labels | Sensitive data copied outside the shared context or relabeled by untrusted code can escape the intended data-flow policy. |
| Scoped content checks | Encoded, split, encrypted or semantically equivalent data may evade a detector unless that representation is explicitly supported and tested. |
| Metadata review | A stable MCP name, schema or description does not prove that the server's implementation is safe or unchanged. |
| No spending oracle | Local cost reservations depend on trusted upper bounds and reported usage. They cannot stop a provider from charging more than the adapter actually constrains. |

For production use with durable tasks, preserve state in a trusted service and define recovery behavior before resuming work after a crash. Do not silently recreate exhausted or revoked tasks with fresh authority. Multiple workers require shared authorization and quota state; separate in-memory guards do not provide an organization-wide limit.

For hostile code or untrusted tool servers, add an operating-system or service boundary, restricted credentials and enforced network controls. Those controls are deployment responsibilities and are not supplied by this alpha.

For MCP, the registered handler is the client bridge promise. The SDK can reject that promise on cancellation before a remote server has stopped. Local concurrency and cost reservations settle with the bridge, so enforce remote concurrency, cost ceilings and cancellation at the server or provider as well. A passing linked-transport SDK test does not establish HTTP/stdio transport security, authentication or remote-server isolation.

## Claims outside this threat model

The alpha does not claim protection against operating-system or runtime vulnerabilities, malicious application administrators, compromised credential stores, arbitrary code execution in its own process, or unauthorized operations performed outside the wrapper. It does not verify the correctness of all model output or detect all prompt injection.

Cross-process authentication, distributed revocation, durable approval replay protection, persisted budgets, secure secret storage and federated agent identity require additional components. A local test of those ideas is not evidence that these distributed guarantees exist. See the [API contract](api-contract.md) for the alpha's local state and charging rules.

## Evidence and failure handling

Record the task, registered tool, canonical resource, policy decision and a stable reason. Avoid putting prompts, raw credentials or unrestricted tool arguments in audit events. An in-memory event or local log is operational evidence, not a signed, tamper-proof audit trail.

Separate policy denials from validation errors, expired approvals, exhausted budgets, handler failures and unknown outcomes. A handler error must not be reported as a prevented side effect: the handler may already have changed external state. Denied or unapproved calls must not start the handler.

The scenario tests should assert actual handler invocation and fixture state, not only the returned decision. Run benign cases alongside hostile cases so a rule that blocks every call does not appear effective. Report unsupported paths and representations directly.

Cost budgets, declared maxima and reported usage use nonnegative safe integer units chosen by the host (for example, microcurrency units). Fractional values and unsafe integers are rejected.
