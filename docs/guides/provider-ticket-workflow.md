# Protected ticket workflow for OpenAI and Anthropic

Both examples use the same Agent Guard host and synthetic ticket store. The model requests a read of ticket `123`, the host reviews the proposed change through a synthetic approval callback, and the host changes that ticket to `resolved`. Ticket `456` belongs to another tenant. Private ticket notes never enter a tool result. The command-line examples replay provider-shaped responses locally and assert the final backend state. They make no network calls and require no API keys.

```sh
npm run build
node examples/providers/openai-responses.mjs
node examples/providers/anthropic-messages.mjs
node --test scripts/provider-ticket.test.mjs
```

Each command prints JSON confirming one permitted read, one approved write, zero forbidden writes and zero provider requests containing the private canary. Failed assertions exit nonzero. The package check also copies these examples into a temporary consumer and runs them using the packed public package, rather than an internal source import.

## Host authority and the point of effect

To practice the operator decision, run `node examples/providers/review-ticket.mjs`
in a terminal after building. It shows the tenant, exact change, expected version
and expiry. Press Enter to keep the ticket open; rerun and type `approve 123`
to see the confirmed new version. Each run uses fresh synthetic records. A pipe,
closed prompt or expired review cannot approve a change. The local practice
identity is not authentication for a deployed service.

[protected-ticket.mjs](../../examples/providers/protected-ticket.mjs) owns the backend, identity, grants, registered tools and approval API. Only the host can access the full records. The provider gets two strict tool declarations, `tickets_read` and `tickets_update`, and the fixed task text. Provider calls cannot supply a tenant, principal, approval, destination, backend operation identity or extra argument.

1. The host validates and copies the arguments. It resolves the ticket's tenant and version from its own store.
2. Agent Guard prepares an immutable action and enforces the task's tenant, resource grants and budget. The entire batch is prepared before any action in it runs. If a call fails preparation, the batch returns errors without effects. A valid caller can retry the valid operation with a fresh correlation ID.
3. For a write, the review callback receives the exact action ID, digest, ticket, target status, resource version and expiry. Its authenticated decision must name that digest. The fixture's automatic synthetic reviewer exists only to make offline testing repeatable. There is no approval tool exposed to the model, and the runner requires a reviewer for writes.
4. Agent Guard consumes the approval once. The handler checks the tenant, cancellation and resource version again immediately before the effect. The backend uses a host-generated operation ID, separate from provider IDs and approval IDs, for its receipt.
5. The read result contains only ticket ID, status, version and bounded public text. A write returns only ticket ID, status and version. Neither returns the private notes, tenant identifier or internal receipt ID.

The shared runner treats a provider ID only as conversation correlation. It rejects duplicate IDs both within a response and across the run. Replaying a prepared action or applying another action's approval also fails. Each host instance supports a single run and is revoked on completion or failure. A new provider ID does not bypass approval. Repeating an approved request for an already resolved ticket makes no additional state change.

## Provider adapters

[openai-responses.mjs](../../examples/providers/openai-responses.mjs) exports `runOpenAITicketWorkflow`. It uses the Responses API shape, sends only synchronous direct function tools, parses complete arguments, preserves the response output items including reasoning, and sends a `function_call_output` for each original `call_id`. Requests set `stream: false` and `store: false`. Current direct caller metadata and absent legacy metadata are both supported. [OpenAI function calling](https://developers.openai.com/api/docs/guides/function-calling)

[anthropic-messages.mjs](../../examples/providers/anthropic-messages.mjs) exports `runAnthropicTicketWorkflow`. It preserves the assistant content, including thinking signatures, and puts all `tool_result` blocks in the immediately following user message. Each result uses the original `tool_use_id`. Tool errors set `is_error: true`. Ticket text stays inside the tool-result block. [Anthropic tool results](https://platform.claude.com/docs/en/agents-and-tools/tool-use/handle-tool-calls)

Both use [workflow.mjs](../../examples/providers/workflow.mjs). A response is copied and bounded before dispatch. Unsupported server tools, hosted-code callers, toolset members, namespace dispatch, asynchronous calls, stream events and partial responses stop the run before any call in that response executes. OpenAI must return a completed response and no explicitly incomplete function call. Anthropic must return `tool_use` or `end_turn` consistent with its content. An incomplete argument object is never executed. To add streaming, first assemble and validate a completed response through the same boundary.

Multiple calls in one provider response are supported. They execute sequentially after preflight so that shared state and approvals have a predictable order. There is no transaction spanning a whole batch. If the first approved action executes and a later action fails, the earlier effect remains. Both success and error results are returned under their original correlation IDs.

## Connecting an application transport

The exported functions accept a trusted `transport(request, { signal })` callback that returns the provider's completed JSON response. They do not import provider SDKs, read environment variables, select credentials or perform HTTP themselves. A host can use its configured SDK clients with automatic retries disabled:

```js
import { createTicketHost } from './examples/providers/protected-ticket.mjs';
import { runOpenAITicketWorkflow } from './examples/providers/openai-responses.mjs';
import { runAnthropicTicketWorkflow } from './examples/providers/anthropic-messages.mjs';

// openai and anthropic are host-created SDK clients, with host-owned credentials.
// requestAuthenticatedReview is the application's review UI/service, not model input.
const common = {
  review: (request, { signal }) => requestAuthenticatedReview(request, { signal }),
  maxTurns: 6,
  maxOutputTokens: 1024,
  timeoutMs: 15_000,
};

await runOpenAITicketWorkflow({
  ...common,
  model: configuredOpenAIModel,
  host: createTicketHost(),
  transport: (request, { signal }) => openai.responses.create(request, {
    signal, maxRetries: 0,
  }),
});

await runAnthropicTicketWorkflow({
  ...common,
  model: configuredAnthropicModel,
  host: createTicketHost(),
  transport: (request, { signal }) => anthropic.messages.create(request, {
    signal, maxRetries: 0,
  }),
});
```

The review service must authenticate the operator and display the reviewed tenant, target and change. Approval returns `{ approved: true, digest, approverId, expiresAt }`; rejection returns `{ approved: false }`. The digest must match the request. The reviewer can shorten the displayed expiry; neither a later callback nor reopening that request can extend it. A callback that blindly returns approval is not human review. Keep the host administration object and full `snapshot()` diagnostic state out of model context.

This wiring is not a live smoke-test command. A live application must supply its own credential storage, permitted endpoint, bounded raw HTTP response reader, transport timeout, cancellation and provider spend policy before using it. The runner's byte cap applies to decoded JSON, after the transport returns. It cannot limit bytes already buffered by an SDK or stop a remote request whose transport ignores cancellation. Do not enable SDK retries, hosted tools or a separate raw tool dispatcher around this boundary. No SDK dependency or paid provider run was added to this milestone.

## Limits and recovery scope

If preparation or review denies a call, its handler did not run. If a submitted
call fails without a usable result, the runner stops the batch, revokes the task
and raises `TOOL_OUTCOME_UNCONFIRMED` to the **host**, with the host action ID.
It sends no further provider requests. The example's host-only
`lookupWriteReceipt(actionId)` looks up the actual write receipt while this
process lives; a missing receipt means unconfirmed. In a real deployment, persist
the action-to-backend-operation binding before dispatch. Check the backend receipt and the durable
executor's action status before considering another attempt. A transport timeout
or malformed result cannot prove that a write did not happen. A model's final
text is never a receipt; show success to an operator only from verified backend state.
If a later provider turn fails after a confirmed call, the host error carries
`confirmedActions` with its host action references. If task revocation also
fails, the host receives `TASK_REVOCATION_UNCONFIRMED`; stop the dispatcher and
verify authority has been withdrawn. Do not start the whole workflow again.

Defaults are six provider requests, four calls per response, 1,024 output tokens per request, 64 KiB per decoded provider response, 256 KiB per assembled request/history, 8 KiB per tool result, and a 15-second run timeout. Overrides have fixed upper bounds in the runner. The Guard task has a 60-second deadline, six admitted tool calls, one concurrent call and eight synthetic cost units. Reads cost one unit and writes cost two. Those units test tool-budget admission; they do not represent dollars or cap provider billing.

Abort and timeout revoke the host task, reject the pending wait and prevent a late transport or review response from dispatching an action. They do not roll back an action already executed. The synthetic backend performs its checked effect synchronously. A real asynchronous backend must enforce its own cancellation and version check at the actual write, keep durable idempotency receipts, and reconcile unknown outcomes before retrying. For crash recovery and externally running workers, use the existing durable executor patterns rather than treating this in-memory fixture as production persistence.

The fixture demonstrates an enforceable integration contract for a host that owns dispatch. It does not sandbox malicious host code or remove alternate clients the application exposes. No real ticket service, identity provider, paid model behavior or representative attack success rate was tested. Model-loop evaluations and production isolation remain separate milestones.

## Regression coverage

The same fixture can use a dedicated `DurableExecutor` via `createTicketHost({ executor })`. Enable `decisionTraces` on that executor to collect bounded, tenant-scoped lifecycle events and explicit human refusals. The host can inspect or export those events through the [decision trace API](decision-traces.md). No trace is added to provider requests. The executor persists its authority ledger, but this example's ticket store remains in memory; passing a durable executor does not provide ticket persistence or production crash recovery.

[provider-ticket-traces.test.mjs](../../scripts/provider-ticket-traces.test.mjs) runs both protocols through that executor. It reconstructs one approved write and a rejected foreign-tenant write, verifies human refusal prevents admission, scans snapshots and exports for private identifiers and customer text, and confirms failed export followed by retry cannot repeat a ticket effect.

[provider-ticket.test.mjs](../../scripts/provider-ticket.test.mjs) exercises both protocols against the shared backend. It checks permitted reads and exactly one approved state change, foreign tenants, unknown tools, extra authority arguments, missing/denied/mismatched/expired approval, prepared-action replay, backend version changes, caller mutation, complete batch preflight, parallel result correlation, duplicate IDs, malformed and partial responses, unsupported execution contexts, private canaries, hostile public ticket text, abort, late completion after timeout, turn/call/cost limits and directory-alias CLI launch. The default fixture carries current explicit direct-caller metadata; legacy absence is also tested.

These are deterministic offline integration tests. Their oracle is the actual backend state and serialized provider requests, not whether an assistant says it refused an action.

Validation on 4 November 2026 used Node 26.12.0. `npm run check` passed 749 tests and the clean-package consumer checks, including both provider examples and the installed Agent Map commands. Its five opt-in Docker tests were then run separately with the cached pinned image `alpine@sha256:bbfcd601d7cd20d35bb0b8b866ad1a8a0d107ca3e1c20870c75c5ce2c1186d30`; all five passed with zero skips. Thus all 754 tests were exercised across the two runs. The 35 provider-workflow tests also passed on Node 22.13.0. Docker checks ran through the local Docker daemon on macOS and do not certify the separate native platform matrix.

The [model-selected trial runner](model-selected-provider-trials.md) supplies a bounded, opt-in provider transport and measures actual tool decisions on this synthetic host.
