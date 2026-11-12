# Protect a ticket workflow with OpenAI or Anthropic

This example puts the guard between a model and a ticket system. The model may read one
ticket and ask to resolve it. The host checks every tool call, a person approves the exact
change, and the model never sees private ticket notes. The same host code works with the
OpenAI Responses API and the Anthropic Messages API.

## What you will achieve

- Run the example offline for both providers. It needs no API key and makes no network
  call.
- Practice the reviewer's decision in a terminal.
- Connect your own provider client and review screen to the same runner.

## Prerequisites

- Node.js 22.13 or later, and this repository built:

  ```sh
  npm ci --ignore-scripts
  npm run build
  ```

- For step 3 with a live model: your own OpenAI or Anthropic SDK client. This repository
  installs neither SDK.

## Steps

### 1. Run the offline examples

```sh
node examples/providers/openai-responses.mjs
node examples/providers/anthropic-messages.mjs
```

Each replays four provider-shaped responses against a made-up ticket store: read ticket
`123`, try to resolve ticket `456` (which belongs to another tenant), resolve ticket
`123`, then finish.

### 2. Practice the review

```sh
node examples/providers/review-ticket.mjs
```

Run it in a terminal. It shows the tenant, the exact change, the expected ticket version
and when the review expires. Press Enter to refuse. Run it again and type `approve 123` to
approve. Each run starts from fresh made-up records.

### 3. Connect your own transport and reviewer

The runner takes two functions from you: `transport`, which sends one request to the
provider and returns the completed JSON response, and `review`, which shows the change to
a person and returns the decision.

Save this as `ticket-demo.mjs` in the repository root and run `node ticket-demo.mjs`. It
uses a scripted transport so that it runs without a provider.

```js
import { createTicketHost } from './examples/providers/protected-ticket.mjs';
import { runOpenAITicketWorkflow } from './examples/providers/openai-responses.mjs';
import { toolResponse, finalResponse } from './examples/providers/replay.mjs';

// Stand-in for the provider: two scripted responses in the OpenAI Responses shape.
const scripted = [
  toolResponse('openai', [{ id: 'call_1', name: 'tickets_update', args: { ticket_id: '123', status: 'resolved' } }]),
  finalResponse('openai'),
];

const host = createTicketHost();
const result = await runOpenAITicketWorkflow({
  model: 'your-model-id',
  host,
  // Replace with a call to your provider SDK. It must return the completed JSON response.
  transport: async (request, { signal }) => scripted.shift(),
  // Replace with your review screen. It must return the digest it was shown.
  review: async (request, { signal }) => {
    console.log('review:', request.ticketId, '->', request.status);
    return { approved: true, digest: request.digest, approverId: 'reviewer-1', expiresAt: request.expiresAt };
  },
  maxTurns: 6,
  maxOutputTokens: 1024,
  timeoutMs: 15_000,
});

console.log(result.outcomes.map(outcome => outcome.ok));
console.log(host.snapshot().tickets.find(ticket => ticket.id === '123').status);
```

With real SDK clients, the two `transport` functions look like this. Turn the SDK's
automatic retries off, so that a request is never sent twice behind the runner's back:

```js
// OpenAI, with runOpenAITicketWorkflow
transport: (request, { signal }) => openai.responses.create(request, { signal, maxRetries: 0 }),

// Anthropic, with runAnthropicTicketWorkflow
transport: (request, { signal }) => anthropic.messages.create(request, { signal, maxRetries: 0 }),
```

Your `review` function must authenticate the person and show them the tenant, the ticket
and the change from the `request` object (`tenantId`, `ticketId`, `status`,
`resourceVersion`, `expiresAt`). To approve, return
`{ approved: true, digest, approverId, expiresAt }` with the `digest` from the request;
`expiresAt` may be earlier than the one shown, never later. To refuse, return
`{ approved: false }`. A function that always approves is not a review.

Each host from `createTicketHost()` serves one run. Keep the host object and its
`snapshot()` output away from the model.

## What you should see

Step 1 prints one line per provider:

```text
{"provider":"openai","mode":"offline-synthetic-replay","reads":1,"approvedWrites":1,"forbiddenEffects":0,"privateCanaryDisclosures":0,"assertions":"passed"}
{"provider":"anthropic","mode":"offline-synthetic-replay","reads":1,"approvedWrites":1,"forbiddenEffects":0,"privateCanaryDisclosures":0,"assertions":"passed"}
```

One read, one approved change, no change to the other tenant's ticket, and no request to
the provider that contains the private notes. A failed check exits with a non-zero status.

Step 3 prints:

```text
review: 123 -> resolved
[ true ]
resolved
```

## How a call is handled

[protected-ticket.mjs](../../examples/providers/protected-ticket.mjs) is the host. It owns
the ticket store, the task, the two tools (`tickets_read` and `tickets_update`) and the
approval step. [workflow.mjs](../../examples/providers/workflow.mjs) is the runner shared
by both providers; the adapters
[openai-responses.mjs](../../examples/providers/openai-responses.mjs) and
[anthropic-messages.mjs](../../examples/providers/anthropic-messages.mjs) only differ in
message format.

1. The runner copies and size-checks the provider's response. It stops the run before
   anything executes if the response is incomplete or contains something it does not
   support: hosted tools, streaming events or asynchronous calls.
2. The host looks up the ticket's tenant and version in its own store. The model cannot
   supply a tenant, a principal, an approval or any extra argument.
3. The guard prepares every call in the response before any of them runs. If one fails,
   none of the calls in that response runs.
4. For a change, the reviewer receives the exact action. The approval is tied to that
   action's digest and works once.
5. The tool checks the tenant and the ticket version again just before it writes.
6. The model gets back the ticket id, status and version, and for a read a bounded piece
   of public text. It never gets the private notes.

Calls in one response run one after another, with no transaction across them: if the
first succeeds and the second fails, the first stays done.

## Limits

| Setting | Default | Allowed |
| --- | --- | --- |
| `maxTurns` (provider requests per run) | 6 | 1 to 12 |
| `maxCallsPerTurn` (tool calls in one response) | 4 | 1 to 8 |
| `maxOutputTokens` (per request) | 1,024 | 16 to 4,096 |
| `maxResponseBytes` (one decoded provider response) | 64 KiB | 256 bytes to 256 KiB |
| `maxHistoryBytes` (one assembled request) | 256 KiB | 4 KiB to 1 MiB |
| `timeoutMs` (whole run) | 15,000 | 1 to 60,000 |

A tool result is at most 8 KiB. The task behind each host has a 60-second deadline, six
tool calls and a budget of eight made-up cost units (a read costs one, a change two).
The units are not money and do not limit what the provider bills you.

What the example does not do:

- **It keeps tickets in memory.** It is a model for your integration, not a ticket system.
- **It does not limit the network.** The response size limit applies after your transport
  returns. Your transport must set its own timeout, size limit and spending limit.
- **It does not undo a finished action.** A timeout or abort revokes the task and stops
  further calls. A change that already ran stays.
- **It only protects calls that go through it.** If your application gives the model
  another way to reach the ticket system, the guard does not see it.

## What can go wrong

A refused call does not stop the run. It appears in `result.outcomes` with `ok: false` and
an `error` code, and the model is told. The other codes below are thrown by the runner and
end the run.

| Symptom | Cause | Fix |
| --- | --- | --- |
| `review-ticket.mjs` prints "No interactive terminal" | Input or output is piped. | Run it directly in a terminal. |
| An entry in `result.outcomes` has `error: "REVIEW_REQUIRED"` | A change was requested and no `review` function was given. | Pass `review`. |
| An outcome has `error: "REVIEW_DENIED"` | The reviewer returned `{ approved: false }`. | Expected. The tool did not run. |
| An outcome has `error: "APPROVAL_INVALID"` | The reviewer returned a different `digest` or a later `expiresAt`. | Return the digest from the request and an `expiresAt` no later than the request's. |
| `INVALID_CONFIGURATION` | A setting is outside the allowed range, or `model`, `transport` or `host` is missing. | Check the limits table. |
| `INVALID_TASK` | The same host was used for a second run. | Call `createTicketHost()` again. |
| `INCOMPLETE_RESPONSE`, `UNSUPPORTED_CALLER`, `UNSUPPORTED_TOOL_OR_CONTENT` | The provider returned a partial response, a hosted tool call or another unsupported item. Nothing in that response ran. | Send completed, non-streaming responses with only these two function tools. |
| `WORKFLOW_TIMEOUT`, `WORKFLOW_ABORTED` | The run timed out or your `signal` aborted it. The task was revoked. | Start a new run with a new host. Check first whether a change already ran. |
| `TOOL_OUTCOME_UNCONFIRMED` | A call was sent to the tool and no usable result came back. The run stopped and the task was revoked. The change may or may not have happened. | Do not retry. Look up the real result in your backend. In the example, `host.lookupWriteReceipt(actionId)` does this. |
| `TASK_REVOCATION_UNCONFIRMED` | The run failed and revoking the task also failed. | Stop sending calls and confirm that the task can no longer act before you do anything else. |

When a run fails after some calls succeeded, the error carries `confirmedActions`: the
calls that did finish. Do not start the whole workflow again without checking them. The
model's final text is never proof that a change happened. Show success to a person only
from what your backend recorded.

## Next steps

- [Decision traces](decision-traces.md): pass a `DurableExecutor` created with
  `decisionTraces` to `createTicketHost({ executor })` to record each decision.
- [Measure a live model on the protected ticket workflow](model-selected-provider-trials.md).
