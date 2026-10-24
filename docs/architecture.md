# Architecture

The npm implementation uses one TypeScript core. A framework or MCP adapter translates a request into a registered tool and a trusted resource resolution. It does not create an independent policy engine.

```text
model request
  -> host selects an opaque task handle
  -> immutable JSON invocation and trusted resource resolution
  -> grants + tenant + metadata + sensitivity + custom policy
  -> optional host-authenticated exact-action approval
  -> fresh state validation + approval consumption + quota reservation
  -> registered handler with AbortSignal
  -> usage reconciliation and result
```

The host registers implementations, approves tool fingerprints, creates root task grants, issues approvals, installs policy and revokes authority. These are administrative capabilities. They must never be exposed as model tools. Caller-supplied identifiers in argument JSON cannot replace the trusted task identity or resource service's ownership information.

Preparing an action copies its JSON arguments and records the tool registration and policy revision. The executor recognizes task handles and prepared actions by object identity. Copying or fabricating either object does not grant access. Replacing a tool implementation invalidates earlier preparations even if public metadata is unchanged.

Policy evaluation may await a remote service. On return, the core rechecks current authority and restrictions. Reservations and approval consumption happen synchronously before calling the registered handler. Every ancestor accounts for its descendants' usage. This provides atomic admission within one JavaScript process, not across workers or machines.

Sensitivity is monotonic within a task tree. This alpha denies external sends after a trusted sensitive read is admitted. There is no automatic classifier or declassification workflow. Literal secret scanning visits nested string values; it is additional detection, not a replacement for restricting sensitive-data access and export.

The core is implemented in TypeScript and has no third-party runtime dependencies. Integrations with external policy evaluators need their own conformance tests. Reusing an external evaluator must not transfer authority over identity, action binding, approvals or resource access to untrusted inputs.

## Later work

- Durable state that keeps reservations and approval consumption consistent and supports recovery after a restart.
- Provider-specific cost ceilings and resource-side idempotency for uncertain outcomes.
- HTTP/stdio and authenticated MCP transport tests, additional SDK/protocol versions, and explicit coverage for resources/read and other privileged methods. The current suite exercises the official SDK v2.4.0 over its linked in-memory transport.
- Stronger isolation and credential custody supplied by the deployment host.
- Detector integrations with measured accuracy, framework adapters and independent security review.

These features are not implemented. The alpha supports local integration experiments and conformance testing.
