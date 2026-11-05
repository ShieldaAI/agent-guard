# Privacy-preserving decision traces

The durable executor can retain a bounded, tenant-scoped record of tool decisions without retaining tool arguments, results or customer identifiers in that record. Enable it on the trusted host. Export runs only when the host explicitly requests it, outside admission and ledger transactions.

```ts
import { DurableExecutor, type DecisionTraceSnapshot } from '@shieldaai/agent-guard-executor';

const executor = new DurableExecutor({
  database: '/private/agent-guard/state.sqlite',
  encryptionKey: hostEncryptionKey,
  decisionTraces: {
    maxEventsPerTenant: 256,
    maxTenants: 64,
    retentionMs: 3_600_000,
  },
});

// Authenticate the observer before selecting its tenant. These are host APIs.
const snapshot: DecisionTraceSnapshot = executor.decisionTraceSnapshot({
  tenantId: authenticatedTenant,
  limit: 100,
});

const exported = await executor.exportDecisionTraces(
  { tenantId: authenticatedTenant },
  async (batch, { signal }) => {
    await hostConfiguredExporter(batch, { signal });
  },
  { timeoutMs: 5_000 },
);
```

`hostEncryptionKey`, `authenticatedTenant` and `hostConfiguredExporter` are supplied by the application. The library selects no destination, reads no provider credential and starts no exporter timer. Neither task credentials nor HTTP task endpoints grant access to these host APIs. Applications exposing traces through their own HTTP service must authenticate observers, derive allowed tenant scope on the server, and bound the transport. Do not expose the executor administration object to an agent.

## Event contract

Each event contains a per-tenant sequence, a random session reference, observation time, lifecycle event, outcome, an allowlisted code, opaque tenant/task/action references, policy epoch, tool registration revision and elapsed milliseconds. Payloads, prompts, arguments, outputs, tool names, resource identifiers or versions, principals, human identities, approval IDs/digests, credentials, receipts and exception messages/stacks are absent.

Tenant, task and action references use separate HMAC domains, the tenant scope, and a trace key derived from the protected ledger key and persisted ledger identity. The same task/action remains joinable after restart under that key and ledger. References change for an unrelated ledger or key rotation. Restoring the same ledger preserves correlation. These are pseudonyms: decision patterns, timing and relationships may still be sensitive. Restrict exporter access and retention accordingly. A reference cannot authenticate a caller, grant permission or approve an action.

| Event | Meaning |
| --- | --- |
| `prepare / PREPARED` | A durable immutable action exists. `REVIEW_REQUIRED` indicates an approval is needed. |
| `deny / DENIED` | Preparation, approval, reconciliation or pre-admission execution failed. A stable error code explains the gate. |
| `review / APPROVED` | The host issued an approval. This is distinct from using it. |
| `review / DENIED` | The host explicitly recorded a negative review using `recordReviewDecision(actionId, 'denied')`. |
| `admit / ADMITTED` | Reservation and approval consumption committed before the handler was invoked. |
| `settle / SUCCEEDED` | The handler returned a valid result and durable settlement committed. |
| `unknown / UNKNOWN` | The admitted handler outcome requires reconciliation, including work found running during restart. |
| `error / ERROR` | The caller received an error after admission. This does not claim that the effect was prevented. |
| `cancel / CANCELLED` | A prepared action was cancelled before dispatch. |
| `cancel / CANCEL_REQUESTED` | Cancellation was requested for an action that was no longer prepared. This does not establish that work stopped. |
| `reconcile / SUCCEEDED` or `FAILED` | The host reconciled unknown work using its separate backend evidence. The evidence text is not traced. |

For example, cancellation observed after a successful effect produces `settle / SUCCEEDED` followed by `error / ERROR` with `EXECUTION_ABORTED`. A throwing handler produces `unknown / UNKNOWN` followed by its caller error. It does not produce a misleading execution denial after admission. Host-defined errors export `OPERATION_FAILED` unless their own data property names an explicitly allowed code. Error accessors are never evaluated for tracing.

`recordReviewDecision` records a refusal, without changing authority. The application remains responsible for deciding whether to cancel the prepared action or allow a later authenticated reconsideration. There is no arbitrary event/payload append API. Unknown task identities and unknown action-only operations cannot be safely assigned to a tenant and are not traced. Authentication and malformed HTTP request handling remain the hosting service's responsibility. The existing ledger audit and admin audit endpoint remain separate and retain their existing raw-ID contract.

## Bounded retention and scope

Defaults retain 256 events for each of at most 64 observed tenants for one hour. Supported bounds are 1–4,096 events per tenant, 1–256 tenants and 1–86,400,000 milliseconds retention. Buffers are volatile and separate from the encrypted authority ledger. They are cleared on close or process loss. Old lifecycle events are not reconstructed from the audit; restart emits fresh `RECOVERY_UNKNOWN` events only for durable actions that were admitted or running. Durable outcomes and reconciliation continue to live in the authority ledger.

An overflow drops the oldest event in that tenant's buffer and increments its `dropped` count. Expiry increments its `expired` count. Buffer slots for observed tenants remain allocated for the session, even after their events expire, so counters cannot be reset by churn. Once all tenant slots are allocated, events from additional tenants are omitted. `decisionTraceStatistics()` reports `tenantCapacityDrops` and the number of allocated buffers. It is an explicitly host-global health API and must not be returned to tenant observers. Trace loss never blocks or changes authorization.

`decisionTraceSnapshot` accepts one `tenantId`, optional `taskId`, `afterSequence` and `limit`. A task filter is checked against the tenant. Results and events are frozen copies. `nextSequence` is the last returned sequence, suitable for the next `afterSequence`; combine it with `sessionRef` because sequences restart in each session. `retained` counts currently matching events after the cursor, before pagination. `dropped`, `expired`, `exported` and `exportFailures` count only that tenant's activity. A task filter does not narrow those tenant-level counters. `accepting` means this tenant already has an allocated buffer. An unobserved tenant always reports false, with no events/counters, regardless of other tenants' activity. Check the separate host-global statistic to diagnose tenant-capacity loss.

Observation uses independent wall/monotonic clocks and never invokes the authorization clock or advances its watermark. Trace timestamps use wall-clock time; latency and retention use the monotonic process clock. Traces record policy/tool revision numbers, not raw version strings or argument fingerprints.

## Export failures and retries

`exportDecisionTraces({ tenantId }, sink, { timeoutMs })` snapshots that tenant's retained events and invokes the supplied callback asynchronously. The default timeout is five seconds, configurable from 1 to 60,000 milliseconds. It returns a stable `{ status, count }` result:

- `exported` acknowledges just the captured sequence range and removes those retained events. Events recorded during export remain queued.
- `failed` or `timeout` retains events for a later retry and increments the tenant's export-failure count. Error messages are discarded. The timeout signals cancellation to the exporter.
- `busy` starts no additional exporter for a tenant with an outstanding export.
- `empty` invokes no exporter because there are no retained events.

If the exporter ignores cancellation and never settles, further exports for that tenant remain busy. This prevents repeated timeouts from accumulating unbounded pending callbacks and batches. Recording continues with normal retention and overflow rules. Closing the executor clears its buffers and signals pending exporters, but cannot retract data already handed to a trusted callback.

Export is best effort with possible duplicates. Volatile retention, overflow and process loss can discard events, so there is no durable at-least-once guarantee. A remote service may accept a batch before the exporter throws or times out, so use `(sessionRef, tenantRef, sequence)` to deduplicate events at the destination. A late success after timeout does not acknowledge the buffer automatically. Export failure does not replay a tool, issue an approval, refund a reservation or alter settlement. Callbacks run only in explicit export calls; there is no callback on the admission path. They are trusted application code, not a sandbox, and must not be given independent tool-dispatch authority.

## Verification

[Trace regression tests](../../packages/executor/test/traces.test.mjs) exercise the full decision chain, absence of raw canaries, immutable snapshots, tenant/task boundaries and counters, foreign-action attempts, full buffers, retention, tenant-capacity loss, failed/retried/hung exports, concurrent exports, parallel approvals, review refusal, cancellation, unknown effects, recovery correlation, forged error codes and accessor traps. [Provider workflow tests](../../scripts/provider-ticket-traces.test.mjs) run both OpenAI and Anthropic ticket fixtures through the durable host and reconstruct actual permitted/forbidden effects from their traces.

```sh
npm run build
node --test packages/executor/test/traces.test.mjs scripts/provider-ticket-traces.test.mjs
npm run check
```

The existing `runAdmissionPhase` export in [benchmark-admission.mjs](../../scripts/benchmark-admission.mjs) accepts `decisionTraces: true` to compare the same file-backed, independent-worker workload with observation enabled. The default benchmark remains unchanged. Measure trace-enabled and disabled phases on the deployment hardware; local latency evidence is not a production service guarantee. Export transport latency is outside admission because export is explicit.

Validation on 4 November 2026 used Node 26.12.0. `npm run check` passed all 771 tests with zero skips and the clean-package consumers. This run included all five opt-in Docker tests using the cached pinned Alpine image `alpine@sha256:bbfcd601d7cd20d35bb0b8b866ad1a8a0d107ca3e1c20870c75c5ce2c1186d30`. The package consumer compiled the public trace types and exercised snapshot/export privacy. All 17 trace and provider-trace tests also passed on Node 22.13.0. Fixtures used synthetic data and offline provider transports; no paid model, production ticket service or live exporter was used. Docker evidence is local to macOS and does not certify the separate native platform matrix.

The [local admission comparison](../validation/decision-trace-admission-2026-11-04.json) used four phases in disabled/enabled/enabled/disabled order, each with 30 warmups and 100 measured calls against 100 tasks and 1,000 grants. All 520 calls, including warmups, produced exactly one effect each; both traced phases retained all 390 expected events with zero drops. The first implementation added 2.60 ms at p95 (16.1%) because observation read the ledger again. Reusing the existing authority snapshot removed that work. The final run measured 16.09 ms disabled and 15.32 ms enabled. Treat the negative difference as timing variation, not a tracing speedup. This is local regression evidence with no outlier exclusion, not a production performance guarantee. The artifact retains the initial result, final phase timings, workload, runtime and final source hashes.
