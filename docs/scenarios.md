# Protection scenarios

These ten scenarios define the acceptance contract for the TypeScript alpha. They concern calls made through one registered-tool executor, using task context established by trusted application code. They do not certify all tool paths, prompt-injection attacks or deployment environments. Read the [threat model](threat-model.md) and [API contract](api-contract.md) before relying on a scenario.

The examples use fake data and fixture handlers. They should run without production credentials or external side effects. “Denied” means the handler is not invoked. “Allowed” means the fixture records exactly the intended effect. An approval request is not permission to execute until the host's reviewer has approved the exact action and the executor has validated that approval. Reviewer authentication belongs to the host, not to an `approverId` string supplied by a caller.

## Common fixture and assertions

Use two tenants, `alpha` and `beta`; a trusted user, `user-1`; a parent task, `task-1`; and a delegated child task. Register tools that read documents, write a message to an outbox and remove a fixture record. Give each record a canonical tenant-qualified identifier.

The host creates the task context and grants. The model supplies tool arguments. Keep an invocation ledger and compare resource/outbox state before and after each request.

For every hostile case, assert:

- No unauthorized handler invocation or side effect occurs.
- The outcome identifies the failed check with a stable reason.
- Sensitive values are absent from the returned error and audit evidence.

For every benign case, assert the intended operation succeeds with the expected scope. If a scenario requires approval, its benign case includes a valid independent approval. A test that blocks everything does not satisfy the contract.

Use a controllable clock for expiry tests and explicit synchronization for concurrent calls. Do not rely on long sleeps or accidental timing. Distinguish library tests from tests of a particular host or MCP integration.

## S01 — Deny unknown tools and unauthorized resources

**Boundary:** a trusted registry maps each tool to its handler and resource resolver. The host validates the tool-specific argument schema; the core validates and freezes the JSON shape and resolved action. The executor applies exact tool/resource grants before dispatch. Resource `*` is an explicit wildcard, not an implicit default.

**Hostile case:** allow `read_document` only for `alpha/docs/guide`. Request an unregistered tool, then request the registered tool for `alpha/docs/payroll`. Both calls are denied and the invocation ledger stays empty. An argument claiming to be an administrator does not change the result.

**Benign case:** read `alpha/docs/guide` through the registered tool. One invocation returns the guide.

**Integration requirement:** canonical resource identifiers must come from trusted validation and resolution. If a file alias, redirect or service-side lookup can change the actual resource, the handler must enforce the same scope at use time. A descriptive tool name does not establish that it is harmless.

## S02 — Reduce authority along local delegation

**Boundary:** trusted host code creates child task handles under a parent and limits their grants to the applicable parent, user and task authority.

**Hostile case:** the user may read and write alpha documents, but the parent task may only read `alpha/docs/guide`. A child requests a write, a different document or a broader grant for a grandchild. Deny all three. Supplying another parent or task name in tool arguments does not widen authority.

**Benign case:** a child with a narrower read grant reads the permitted guide. Its trusted parent/task relationship remains visible in the decision context.

**Integration requirement:** the alpha's handles are local context, not credentials accepted by another process. Remote or federated delegation requires authentication and grant verification outside this contract. Do not deserialize model-provided identifiers into trusted task authority.

## S03 — Keep administration outside untrusted content

**Boundary:** policy changes, task issuance, approval decisions and credential administration belong to the trusted host. They are not ordinary model-callable operations.

**Hostile case:** a retrieved document tells the agent to disable checks, approve its own action or change a secret's audience. The agent requests an unregistered administration tool, a registered control-plane tool without control-plane authority, or supplies fields claiming approval. Deny the request; policy, approval and credential state remain unchanged.

**Benign case:** a separately authorized host administrator makes an explicit policy change through the application's administration interface. A subsequent permitted read uses the resulting policy.

**Integration requirement:** this protects the exposed tool boundary. It does not stop an attacker who can execute JavaScript in the host process, modify application files or invoke administrative functions directly. Protect those paths through the host's deployment controls.

## S04 — Constrain external sends after sensitive access

**Boundary:** a trusted resolver marks sensitive access in a context shared by parent/descendant tasks and supplies canonical outbound recipients or resources. Once sensitive, that context cannot dispatch an external action. Custom policy and approval cannot weaken this mandatory restriction.

**Hostile case:** the task receives untrusted ticket text and reads a document marked sensitive. It then sends that data to an unauthorized recipient, including a recipient on an otherwise allowed domain. Deny the send before the outbox changes. A locally delegated child does not escape the relevant shared context.

**Benign case:** a task family that has not accessed sensitive material sends public fixture content to its explicitly permitted recipient. The outbox contains exactly one intended message. The alpha does not provide an approval override or declassification operation for a sensitive context.

**Integration requirement:** sensitivity is a host assertion, not automatic tracking of every byte or general untrusted-content provenance analysis. All related tools must use the relevant shared context, and the host must retain sensitivity when it copies data into another root task. A raw HTTP client or a second independent executor is outside this boundary.

## S05 — Require exact, expiring, single-use approval

**Boundary:** a trusted reviewer approves a specific action; the executor validates the action and consumes approval once before dispatch.

**Hostile case:** request deletion of fixture record A, obtain approval, then change the target or arguments. Deny the changed action. Reuse the approval twice concurrently: at most one matching operation may start. Approve before expiry but delay consumption until after expiry: deny. A revoked task cannot use an earlier approval.

**Benign case:** approve the unchanged action, execute it before expiry and record one deletion of A. The approval is unavailable for another execution.

**Integration requirement:** single-use consumption applies within the same live executor. It does not provide durable replay protection across restarts or a transaction with an external service. Handlers need idempotency or reconciliation for an uncertain outcome. Where a resource can change after approval, bind or revalidate its version at the service boundary.

## S06 — Review MCP tool-definition changes

**Boundary:** the MCP integration associates calls with an approved tool definition and prevents calls that do not match the accepted definition.

**Hostile case:** accept definition v1, then supply v2 with a changed description/schema or an added tool. A call using unapproved metadata must not reach the server through the wrapper. An innocuous name must not automatically grant a newly discovered tool authority.

**Benign case:** unchanged v1 remains usable. After trusted host code reviews and accepts v2, an otherwise authorized call may use v2.

**Integration requirement:** only metadata observed and checked by the wrapper is covered. Stable metadata does not prove that a server's code or behavior is unchanged. The host must establish its trusted baseline, route protected calls through the wrapper and define what happens when the process restarts. A raw transport bypass is not protected.

## S07 — Stop configured secrets and canaries in arguments

**Boundary:** the configured content check inspects validated outbound arguments before a registered handler starts.

**Hostile case:** put a configured fake secret or canary in a nested outbound string argument. Deny before any bytes reach the fixture sink; approval cannot bypass the mandatory check. A JSON Unicode escape that the host parser decodes into the same string must match identically. Encoded strings whose decoded values are not supplied to the scanner, such as base64, are outside the literal scanner's guarantee.

**Benign case:** send public text and similar-looking nonsecret identifiers. The intended content reaches the fixture sink; no secret appears in evidence.

**Integration requirement:** this is detection of configured values/patterns on inspected arguments. It does not establish that every secret is known or detect arbitrary encodings, split messages, screenshots or semantic paraphrases. A handler that reads a secret internally or uses another network path needs separate controls.

## S08 — Recheck revocation, policy and approval before dispatch

**Boundary:** the executor uses current local task and policy state when it admits a protected call, including after an approval wait.

**Hostile case:** start a privileged request, then revoke its task before approval is consumed. Deny even if the approval is subsequently granted. Also deny a request with missing/expired approval, or when a custom policy throws or returns an invalid decision; a failed check must not fall back to running the handler. Changing policy invalidates a previously prepared action. Omitting an optional custom policy is not a policy failure: all mandatory checks still apply.

**Benign case:** an unrevoked task, valid current policy and timely approval permit the intended operation.

**Integration requirement:** revocation governs future dispatch in the same live executor. It cannot retract an operation already accepted by a remote service or force an uncooperative handler to stop. There is no distributed revocation service or persisted lease guarantee in this alpha. The host must define recovery after policy/state loss.

## S09 — Use trusted tenant context

**Boundary:** trusted host context identifies the tenant, and registered tools validate resource ownership against that context.

**Hostile case:** an alpha task requests a beta resource while tool arguments claim `tenant: beta`, claim an alpha alias or omit tenant entirely. Deny before reading or changing beta data. A beta approval cannot authorize an alpha task.

**Benign case:** the alpha task accesses an explicitly granted alpha resource. Return only that resource's result.

**Integration requirement:** a tenant string in model output is a request field, not authenticated context. The application remains responsible for authenticating its user and for verifying ownership in the service or database used by the handler. The guard does not discover tenant ownership independently.

## S10 — Bound admitted work

**Boundary:** local budget reservations govern calls admitted by one live executor and update the applicable task ancestors. Deadlines are checked at admission; cancellation of running handlers is cooperative. Tool `maxCost` is a host-supplied upper bound that the adapter must actually enforce.

**Hostile case:** configure three calls, one concurrent action, a small cost budget and a short task deadline. Submit a burst: no more than three calls may start, and active handlers must not exceed the concurrency limit. Deny admission when the tool's maximum cost cannot fit in the remaining budget. After the deadline, a new call is denied. A cooperative fixture observes cancellation and stops; an uncooperative handler is explicitly outside the cancellation guarantee. An invalid or over-bound actual-cost report causes an error and task revocation; it does not undo a provider charge that already occurred.

**Benign case:** two short authorized calls complete within the limits and report valid actual costs at or below their declared maxima. Concurrency reservations are released when the handlers settle, and counters match the documented charging rule. A handler failure must not accidentally create extra authority or permanently retain a concurrency slot. If a handler omits actual cost, charge its declared maximum.

**Integration requirement:** budgets are in-memory and per executor. Restarting, duplicating the process or issuing a new root task can create fresh state; the host must not use those actions to resume an exhausted task. A child's work also consumes its ancestor budgets. Call counts are not token or monetary limits. A cost budget controls declared local units; a monetary claim requires accurate provider usage accounting and enforced provider bounds. Durable quotas are outside this alpha.

## Reading test results

Passing an individual case means the exercised adapter and configuration prevented that fixture's unauthorized effect while permitting its benign pair. It does not validate other adapters, arbitrary shell execution or all encodings and concurrency schedules.

Keep assertions about handler invocation separate from policy decisions, and report untested/unsupported variants. Add regression cases when an integration exposes a new path. For deployment guarantees beyond one trusted process, test the surrounding authentication, storage, isolation and service enforcement as well.
