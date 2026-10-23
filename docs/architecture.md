# Architecture

The npm implementation uses one TypeScript core. A framework or MCP adapter translates a request into a registered tool and a trusted resource resolution. It does not create an independent policy engine.

```text
model request
  -> host selects an opaque task handle
  -> immutable JSON invocation and trusted resource resolution
  -> grants + tenant + metadata + provenance + custom policy
  -> optional host-authenticated exact-action approval
  -> fresh state validation + approval consumption + quota reservation
  -> registered handler with AbortSignal
  -> usage reconciliation and result
```

The host registers implementations, approves tool fingerprints, creates root task grants, issues approvals, installs policy and revokes authority. These are administrative capabilities. They must never be exposed as model tools. Caller-supplied identifiers in argument JSON cannot replace the trusted task identity or resource service's ownership information.

Each preparation snapshots plain JSON and binds the tool registration and policy revision. The executor retains authority by object identity. A copied or fabricated task/prepared object cannot recover it. Replacing a tool implementation invalidates earlier preparations even if public metadata is unchanged.

Policy evaluation may await a remote service. On return, the core rechecks current authority and restrictions. Reservations and approval consumption happen synchronously before calling the registered handler. Every ancestor accounts for its descendants' usage. This provides atomic admission within one JavaScript process, not across workers or machines.

Sensitivity is monotonic within a task tree. This alpha denies external sends after a trusted sensitive read is admitted. There is no automatic classifier or declassification workflow. Literal secret scanning visits nested string values; it is additional detection, not a replacement for restricting sensitive-data access and export.

The initial implementation is original TypeScript with no third-party runtime dependency. It does not embed Invariant or Microsoft's runtime. Optional contextual-policy integrations can be added after adapter-specific conformance tests. Reusing an external evaluator must not transfer authority over identity, action binding, approvals or resource access to untrusted inputs.

## Later work

- Protected durable state with transactional reservations, approval consumption and restart reconciliation.
- Provider-specific cost ceilings and resource-side idempotency for uncertain outcomes.
- HTTP/stdio and authenticated MCP transport tests, additional SDK/protocol versions, and explicit coverage for resources/read and other privileged methods. The current suite exercises the official SDK v2.4.0 over its linked in-memory transport.
- Stronger isolation and credential custody supplied by the deployment host.
- Measured detector integrations, framework adapters and independent security review.

These are planned integration areas, not current guarantees. The first alpha is deliberately suitable for integration experiments and conformance development.
