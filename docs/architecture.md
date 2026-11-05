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

Sensitivity is monotonic within a task tree. This alpha denies external sends after a trusted sensitive read is admitted. There is no automatic classifier or declassification workflow. Literal secret scanning visits nested object keys and string values; it supplements restrictions on sensitive-data access and export.

The core is implemented in TypeScript and has no third-party runtime dependencies. Integrations with external policy evaluators need their own conformance tests. Reusing an external evaluator must not transfer authority over identity, action binding, approvals or resource access to untrusted inputs.

## When one in-process guard is insufficient

The [durable executor](../packages/executor/README.md) persists reservations and
approval consumption and records uncertain outcomes for reconciliation. The
[managed MCP adapter](../packages/mcp/README.md) pins a reviewed descriptor
and has an explicit, limited set of supported methods. The [isolation
profile](../deployment/README.md) runs selected workloads in a separate,
network-disabled container. None of these components protects calls that bypass it.

Use the [protection design](protection-design.md) to choose components, and the
[verification scorecard](protection-assessment.md) for tested profiles and open
work. The host still owns user authentication, credential custody, atomic checks at
the backend, provider-side spending ceilings and the response to uncertain effects.
Multiple independent SQLite owners do not implement distributed authorization.
