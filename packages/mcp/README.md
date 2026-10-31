# @shieldaai/agent-guard-mcp

Register MCP operations with the same execution boundary used by `@shieldaai/agent-guard`. Node.js 22+, ESM. Experimental alpha.

## Managed connections

`ManagedMcpConnection` owns an official MCP SDK client and a single transport lifetime. It binds the registry to a trusted server/transport identity, principal, tenant, random session ID and monotonically increasing revision. The underlying client is not exposed. Every operation still requires a guard task grant and explicit fingerprint approval.

```js
import { AgentGuard } from '@shieldaai/agent-guard';
import { ManagedMcpConnection, createRestrictedMcpHttpTransport } from '@shieldaai/agent-guard-mcp';

const guard = new AgentGuard();
const transport = createRestrictedMcpHttpTransport({
  endpoint: 'https://reports.example/mcp',
  // Provided by the trusted executor: enforces DNS/IP and network policy at connect time.
  fetch: executorFetch,
  // Obtain a scoped token through your maintained OAuth implementation.
  headers: { Authorization: `Bearer ${scopedAccessToken}` },
});
const connection = await ManagedMcpConnection.connect({
  guard,
  identity: {
    serverId: 'reports', transportIdentity: 'approved-reports-deployment-v3',
    principalId: 'alice', tenantId: 'acme',
  },
  transport,
  tools: [{
    name: 'read',
    resolve: args => ({ resourceId: args.id, tenantId: 'acme' }),
  }],
});
// Review the immutable descriptors and fingerprints before approving them.
for (const tool of connection.registrations) guard.approveTool(tool.name, tool.fingerprint);
// Create a scoped task and use guard.prepare / guard.execute as in the core guide.
// Both core and the durable executor can be used: only registerTool is required here.
```

The transport is exclusively owned by the manager. Do not retain a second client or use its transport outside the manager. `transportIdentity` is a host assertion bound to approved endpoint/launch configuration and authenticated credentials; self-reported server names or model-supplied strings are not authentication. Use one live manager per server namespace in a guard.

### Registry changes and failures

- `tools/list_changed`, `resources/list_changed`, and `prompts/list_changed` quarantine all registered operations synchronously at the transport boundary. They never approve or automatically refresh changed definitions.
- Call `await connection.refresh()` to fetch and validate a fresh bounded registry. Review and approve the new fingerprints. Every refresh, including unchanged descriptors, invalidates prepared calls and previous fingerprint approvals.
- Outbound operations carry session/revision markers checked immediately before transport dispatch, closing the gap between preparation and asynchronous SDK dispatch. Concurrent refreshes cannot publish stale results.
- Closing or losing the connection invalidates the registry. Reconnection requires a new manager and new approvals; it cannot inherit a former session's approval.
- A failed, aborted or invalid-result operation quarantines the connection and is never retried by the manager. A metadata change during execution discards the returned result. Neither action rolls back an effect that already occurred remotely.

`connection.status`, `revision`, `sessionId`, and immutable `registrations` expose state without granting raw protocol access. Missing/removed operations remain unavailable. Task call/concurrency/cost budgets are enforced by the supplied guard/executor.

### Inventory observations

`connection.inventory()` returns an immutable, bounded observation without
network requests, authorization callbacks, resolution or tool execution. It stays
readable after close. The version-1 contract includes host server/principal/tenant
IDs, an opaque session-local `transportRef`, the manager's random `sessionId`,
capture time, lifecycle state and allowlisted operation names/kinds/fingerprints.
It omits descriptors, schemas, resource URIs, endpoint configuration, credentials
and native transport session IDs. Keep secrets out of host IDs and operation names.

`revision` in the observation (also `connection.inventoryRevision`) advances for
inventory lifecycle changes, including refresh completion. `authorizationEpoch`
is the existing `connection.revision`, used by admission. `metadataRevision`
starts at one for the first accepted registry and advances only when its selected
descriptors change, including removals. Refreshing identical descriptors changes
authorization fingerprints but keeps the metadata revision. Reconnection creates
a new manager session and transport reference, with new counters.

Only `ready` observations expose operations with `metadataState: 'current'`.
`connecting`, `refreshing`, `quarantined` and `closed` expose no operations;
metadata is `unobserved` until a registry has been accepted, then `stale`.
Presence and readiness do not establish approval or permission to execute.
The projection permits at most 256 operations and 2 MiB; invalid data, clocks or
limits produce stable `MCP_INVENTORY_*` codes without source values.
See the [executor composition guide](../executor/README.md#mcp-inventory-composition)
and [standalone schema](../../schemas/agent-guard-mcp-inventory-v1.schema.json).

### Supported capability profile

| Surface | Managed profile |
| --- | --- |
| `tools/call` | Only explicitly named bindings; schema-validated arguments; scoped resolver and guard authorization; bounded result validation |
| `resources/read` | Opt-in `resources: [{name, uri, resolve, ...}]`; exact advertised URI; empty argument object; returned content must match that URI |
| `prompts/get` | Opt-in `prompts: [{name, resolve, ...}]`; advertised named prompt; only declared string arguments; guard authorization before retrieval |
| Resources/prompts without bindings | No discovery or dispatch |
| Sampling, elicitation, roots, subscriptions, tasks, unknown requests | Not advertised/supported; server requests are rejected |
| MCP Apps/UI widgets | Unsupported; UI metadata, `ui:` resources and active HTML/JavaScript/SVG MIME content are rejected |
| Links and prompt text | Returned as untrusted data; never automatically fetched, opened, rendered or promoted to instructions |

Resource and prompt retrieval are data access, not proof that returned text is safe to follow. Host applications must retain provenance and keep this content out of privileged instruction channels. Descriptor pinning does not detect a malicious implementation whose descriptor never changes.

Defaults: 10-second request deadline, four discovery pages, 64 total registry entries, 10,000 inbound messages per connection. Configurable values have hard upper bounds. JSON envelopes/results are limited to 1 MiB, 10,000 nodes and depth 32. Schema documents are limited to 64 KiB, 2,048 nodes and depth 16; local-reference expansion has separate limits. The bounded structural JSON Schema profile uses maintained AJV, permits acyclic local JSON-pointer references, and rejects external/dynamic/recursive references, custom dialects, regex patterns and formats. Unsupported schemas fail closed; there is no silent validation downgrade. These structural bounds are not an OS CPU quota; run untrusted protocol processing inside the executor isolation boundary.

### HTTP and authentication boundary

`createRestrictedMcpHttpTransport` uses the official SDK 2.4.0 Streamable HTTP transport with an exact HTTPS endpoint, no redirects, no automatic reconnection and bounded response streams. HTTP is available only for explicit `127.0.0.1`/`[::1]` test or local-executor endpoints with `allowInsecureLoopback: true`. URL credentials and fragments are rejected. The default 1 MiB response-stream limit also bounds long-lived SSE streams; it can be raised up to 16 MiB. Establish a newly reviewed connection after a bounded stream ends.

**The required `fetch` must enforce DNS/IP/egress policy in the trusted executor.** Endpoint validation does not prevent DNS rebinding or an approved hostname resolving to a private address. A global `fetch` is sufficient for the loopback tests, but is not a hardened production network boundary. The wrapper supplies `redirect: 'error'`; the supplied implementation must honor it. It also rejects returned redirect responses and unexpected final response URLs.

This factory does not launch a server, run a shell, open an OAuth URL, discover an issuer, refresh a token or expose a control API. Use a maintained OAuth implementation outside the model-accessible process; verify signatures, issuer, audience/resource, subject, expiry and required scopes before passing scoped credentials. `assertVerifiedMcpClaims(claims, policy, now?)` performs the latter binding checks on **already cryptographically verified** claims, using Unix seconds. It never decodes/authenticates an arbitrary JWT. Never pass merely decoded token contents. A missing/wrong audience is rejected even if the signature was valid. Supply the manager's synchronous `authorize: () => assertVerifiedMcpClaims(verifiedClaims, policy)` callback to recheck expiry/revocation at connection, preparation, discovery and operation dispatch. A thrown error quarantines the connection. Async authorization callbacks are rejected; asynchronous verification belongs in the credential provider before supplying a verified authorization snapshot.

If supplying a custom transport, the executor owns its endpoint/redirect rules, byte limits before parsing, credential custody, authenticated management API, subprocess launch policy, sandbox and operating-system network limits. Native hooks alone do not provide host isolation. The manager's trusted identity strings are not substitutes for these controls.

## Existing single-tool bridge

`registerMcpTool` remains compatible with existing callers that already own their SDK client. It does not provide the managed lifecycle, schema, transport or capability profile described above:

```ts
import { AgentGuard } from '@shieldaai/agent-guard';
import { registerMcpTool } from '@shieldaai/agent-guard-mcp';

const guard = new AgentGuard();
const registered = registerMcpTool(guard, {
  serverId: 'documents',
  tool: { name: 'read', description: 'Read a report', inputSchema: { type: 'object' } },
  client: {
    async callTool(request, { signal }) {
      signal.throwIfAborted();
      // Replace with your SDK call and pass through the abort signal.
      return { content: [{ type: 'text', text: 'Public report' }] };
    },
  },
  resolve(args) {
    if (typeof args.id !== 'string') throw new Error('Invalid arguments');
    // Look up ownership in your resource service.
    return { resourceId: args.id, tenantId: 'acme' };
  },
});
guard.approveTool(registered.name, registered.fingerprint);
```

Grant tasks access to `registered.name`, then use `guard.prepare(task, { tool: registered.name, args })` and `guard.execute(prepared)`. Calling the underlying client directly bypasses the guard.

Names include escaped server and tool identifiers. Every supplied descriptor field is included in fingerprint metadata. Register again when `tools/list` changes and explicitly approve the new fingerprint. Re-registration invalidates earlier prepared calls even when metadata is unchanged. The adapter never approves a tool automatically.

The single-tool client interface is a small host-supplied bridge usable with different MCP SDK versions. The host must validate arguments, resolve tenant/resource/recipient semantics, forward cancellation and prevent unguarded transport access. This bridge covers registered `tools/call` operations only. Tool metadata approval does not authenticate a server or verify its implementation.

For an already connected official SDK v2 `Client`, the bridge is:

```js
// sdk is your connected @modelcontextprotocol/client Client.
const { tools } = await sdk.listTools();
const descriptor = tools.find(tool => tool.name === 'read');
if (!descriptor) throw new Error('Required MCP tool is missing');

const registered = registerMcpTool(guard, {
  serverId: 'documents',
  tool: descriptor,
  client: {
    callTool(request, { signal }) {
      return sdk.callTool(request, { signal });
    },
  },
  resolve: resolveReportFromTrustedStore,
});
// Approve registered.fingerprint after reviewing the descriptor and resolver.
```

The SDK's [client guide](https://github.com/modelcontextprotocol/typescript-sdk/blob/main/docs/clients/calling.md) documents this v2 signature. Older SDK versions may put request options in a different argument position; adapt the bridge for your installed SDK. SDK types permit broader values than this package's JSON contract, so TypeScript hosts must narrow descriptor and result data at that boundary. The guard validates and copies registered metadata and execution results at runtime.

Check `isError` on returned MCP results: tool-level errors remain MCP results and are charged normally. A rejected SDK request becomes a redacted `TOOL_FAILED` error; cancellation becomes `EXECUTION_ABORTED`. Neither is retried automatically. Forwarding cancellation requests cooperative server cancellation. The SDK can reject the local request before a remote handler finishes, so guard concurrency and reservation settlement track the bridge promise, not proof that remote work stopped. Remote effect, concurrency and cost limits require server-side enforcement.

Cost budgets, declared maxima and reported usage use nonnegative safe integer units chosen by the host (for example, microcurrency units). Fractional values and unsafe integers are rejected.

Optional `maxCost` reserves a trusted upper bound. `measureCost(result)` can return verified actual usage; without it the full bound is charged. Provider-side maximum-cost enforcement remains the host's responsibility.

Core JSON limits also apply to MCP results: the full result envelope must fit within 1 MiB of canonical UTF-8 JSON, 100,000 nodes and 64 levels of depth. Large base64 images or embedded resources can exceed that limit; resolve large content through bounded host-controlled resources instead. An oversized result becomes `RESULT_INVALID` and revokes the task after the remote call has occurred.

Integration coverage uses official SDK 2.4.0 linked transports for tool/resource/prompt discovery and execution, metadata changes, denied dispatch, approvals, schema rejection, cancellation, server failures and cost settlement. Real loopback HTTP fixtures verify benign initialization, cross-origin redirect credential denial and stream-size limits. Claim-binding tests do not certify an OAuth provider or cryptographic verifier. Native stdio launch, live identity providers, DNS-pinned networking, arbitrary remote-server behavior and OS isolation require executor/deployment tests. The client SDK is a runtime dependency; the server SDK is used by tests.

Apache-2.0. See the [repository threat model](https://github.com/ShieldaAI/agent-guard/blob/main/docs/threat-model.md).
