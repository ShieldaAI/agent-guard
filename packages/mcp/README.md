# @shieldaai/agent-guard-mcp

This package connects Model Context Protocol (MCP) servers to Agent Guard, so that every MCP tool call, resource read and prompt request passes the guard's grants, approvals and budgets before it reaches the server. It stops calls to tool definitions nobody reviewed, definitions that changed after review, calls by another tenant or principal, requests the server makes back to the client (sampling, elicitation, roots), and oversized or active (HTML, script, widget) content.

```sh
npm install @shieldaai/agent-guard @shieldaai/agent-guard-mcp
```

Node.js 22 or later, ESM. It uses the official MCP client SDK, `@modelcontextprotocol/client` 2.4.0. In this document "the guard" is `@shieldaai/agent-guard`, "the executor" is `@shieldaai/agent-guard-executor`, and "the host" is your trusted application code.

## Quick example

```ts
import { AgentGuard } from '@shieldaai/agent-guard';
import { ManagedMcpConnection, createRestrictedMcpHttpTransport } from '@shieldaai/agent-guard-mcp';

// Supplied by the host: a fetch that enforces your network policy, and a token for this server.
declare const hostFetch: typeof fetch;
declare const accessToken: string;

const guard = new AgentGuard();
const connection = await ManagedMcpConnection.connect({
  guard,
  identity: {
    serverId: 'reports',
    transportIdentity: 'reports-deployment-v3',
    principalId: 'alice',
    tenantId: 'acme',
  },
  transport: createRestrictedMcpHttpTransport({
    endpoint: 'https://reports.example/mcp',
    fetch: hostFetch,
    headers: { Authorization: `Bearer ${accessToken}` },
  }),
  // Only the operations you name are loaded. `resolve` says which resource a call touches.
  tools: [
    {
      name: 'read',
      resolve(args) {
        if (typeof args.id !== 'string') throw new Error('id must be a string');
        return { resourceId: args.id, tenantId: 'acme' };
      },
    },
  ],
});

// Approve only the definitions a person reviewed: compare each digest with the one on record.
// The record is keyed by the registered name, which carries the server ID and the remote name.
const reviewed = new Map([['mcp:reports:read', 'sha256:<digest recorded at review>']]);
for (const tool of connection.registrations) {
  if (reviewed.get(tool.name) === tool.descriptorDigest) guard.approveTool(tool.name, tool.fingerprint);
}

// From here on it is the guard's normal flow: a task with grants, then prepare and execute.
const task = guard.createTask({
  id: 'research-1',
  principalId: 'alice',
  tenantId: 'acme',
  grants: [{ tool: 'mcp:reports:read', resources: ['report-1'] }],
  budget: { maxCalls: 5, maxConcurrent: 1, maxCost: 0, deadline: Date.now() + 60_000 },
});
const prepared = await guard.prepare(task, { tool: 'mcp:reports:read', args: { id: 'report-1' } });
console.log(await guard.execute(prepared));
```

`guard` can be the in-memory guard or the executor: the connection only needs `registerTool`.

## How a connection works

`ManagedMcpConnection` owns one MCP client and one transport. It loads only the tools, resources and prompts you bind by name, checks each definition, and registers the accepted ones with the guard, unapproved. A tool is registered as `mcp:<serverId>:<name>`, a resource as `mcp-resource:<serverId>:<name>` and a prompt as `mcp-prompt:<serverId>:<name>`, with both parts URL-encoded. The encoded name may be at most 4,096 characters, the guard's limit for a tool name; a server ID or binding name that would exceed it fails with `INVALID_CONFIGURATION` when the connection is created.

`identity` is the host's statement of which server this is and who it is used for. A task with a different `principalId` or `tenantId` cannot use the connection (`IDENTITY_DENIED`). `transportIdentity` names the reviewed endpoint or launch configuration; a name the server reports about itself is not authentication. Use one live connection per `serverId` in a guard.

`connection.status` is `ready` when operations can run. In `quarantined`, `refreshing` and `closed` every registered operation is unavailable. The connection takes ownership of the transport and never exposes the underlying client; do not use that transport anywhere else.

## Pin tool definitions

Each entry in `connection.registrations` carries two identifiers:

- `fingerprint` is what `guard.approveTool()` takes. It changes on every connection and every refresh, so it cannot be stored.
- `descriptorDigest` is a `sha256:` digest of the kind, the remote name and the accepted definition. It stays the same while the server advertises the same definition.

The first time, read `tool.descriptor` and `tool.descriptorDigest` from `connection.registrations`, have a person review the definition, and record the digest. After that, approve only when the digest matches, as in the example above. A new or changed definition has a different digest and stays unapproved.

Record each digest under the server ID and the remote name, for example under `tool.name` as above. The digest covers the definition only, not the server, so the same definition on another server has the same digest: a record keyed by the remote name alone would approve a tool on a server nobody reviewed.

This is the "pin tool definitions by hash" control of the [OWASP MCP Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/MCP_Security_Cheat_Sheet.html). It detects a changed definition, not a server that changes its behaviour behind an unchanged one.

## When the server changes or fails

A failure that concerns one call fails only that call, with `TOOL_FAILED` from the guard: a request timeout, an error reply, an invalid or oversized result, a resource mismatch, or a throwing `measureCost`. A call cut short because its task was revoked or reached its deadline fails with `EXECUTION_ABORTED`. In both cases other tasks keep using the connection, and the call is never retried.

A failure that concerns the connection quarantines it: a `list_changed` notification, a failed send, an authorization failure, a call that fails because it needed a request this package refuses, active content in a result, too many inbound messages, or a malformed or oversized message that answers no call. Quarantine takes effect at once, and prepared calls no longer run. A server request for sampling, elicitation or roots is answered with an error and does not quarantine. Losing the transport closes the connection instead (see below).

```js
if (connection.status === 'quarantined') {
  console.log(connection.failureReason); // for example REGISTRY_CHANGED
  await connection.refresh();
  console.log(connection.skipped); // [{ kind, remoteName, reason }]
  // Compare each descriptorDigest again, then approve the new fingerprints.
}
```

- `failureReason` is the code behind the last quarantine or forced close, for example `REGISTRY_CHANGED`, `MESSAGE_BUDGET`, `MESSAGE_REJECTED`, `AUTHORIZATION_DENIED`, `CREDENTIAL_REFLECTED`, or `CONNECTION_UNAVAILABLE` when the transport closed or a send failed. It is `undefined` after a successful refresh, and your own `close()` does not set it.
- `skipped` lists the operations you bound that the server advertised but the last refresh could not accept, each with a `reason` such as `SCHEMA_UNSUPPORTED`, `SCHEMA_REFERENCE_DENIED` or `ACTIVE_CONTENT_DENIED`. A skipped operation is not registered and cannot be called; the others load normally.
- `refresh()` loads the registry again. Every refresh issues new fingerprints, even for unchanged definitions, so each operation needs a new approval and earlier prepared calls fail. It rejects with `REGISTRY_REJECTED` when the server's registry was refused, and with `CONNECTION_CHANGED` when something else changed the connection first: a newer refresh, a change notification, an authorization failure or a close.
- A message that contains one of your `protectedValues` closes the connection. So does losing the transport. A closed connection cannot be refreshed: create a new one and approve again.

No failure undoes an effect that already happened on the server.

## What is supported

| MCP feature | Support |
| --- | --- |
| `tools/call` | Bound tools only. Arguments are checked against the advertised schema before the guard resolves the call. |
| `resources/read` | Opt-in with `resources: [{ name, uri, resolve }]`. The exact advertised URI only; returned content must carry that URI. |
| `prompts/get` | Opt-in with `prompts: [{ name, resolve }]`. Only the declared string arguments. |
| Resources and prompts without a binding | Not listed and not callable. |
| Sampling, elicitation, roots, subscriptions, tasks, unknown requests | Not advertised; a server request is answered with an error. |
| MCP Apps and UI widgets | Refused: UI metadata, `ui:` resources and HTML, JavaScript or SVG content. |
| Links and prompt text in results | Returned as data. Nothing is fetched, opened or rendered. |

Text returned by a server is not safe to follow as instructions. Mark a connection (or one binding) with `readsUntrusted: true` when people outside your trust boundary can write what it returns; the guard then applies each tool's `untrustedContext` rule. Bindings also accept `requiresApproval`, `controlPlane`, `maxCost`, `measureCost`, `untrustedContext` and `sendsExternal`, with the same meaning as in the guard.

## Limits

| What | Default | Option |
| --- | --- | --- |
| One protocol message in either direction, and so one result | 1 MiB | `limits.maxMessageBytes`, up to 16 MiB |
| Values and nesting in one message | 10,000 values, 32 levels | fixed |
| Call arguments | 1 MiB | fixed |
| All advertised definitions together | 1 MiB | fixed |
| One schema | 64 KiB, 2,048 values, 16 levels | fixed |
| Bindings, and definitions the server advertises | 64 | `limits.maxEntries`, up to 256 |
| Pages read from one list request | 4 | `limits.maxPages`, up to 16 |
| Time for one request | 10 s | `limits.requestTimeoutMs`, up to 120 s |
| Inbound messages | 10,000 per 10 s | `limits.maxMessages`, `limits.messageWindowMs` |
| HTTP response or stream | 1 MiB | `maxResponseBytes`, up to 16 MiB |
| Protected values | 32 | fixed |

A result over the message limit fails that call with `TOOL_FAILED`; the connection and the task stay usable. The guard then applies its own `limits.maxJsonBytes` (1 MiB by default) to the result, and a result the guard refuses fails with `RESULT_INVALID` and revokes the task. With the default limits the connection's limit is reached first. If you raise `limits.maxMessageBytes`, raise the guard's `limits.maxJsonBytes` to at least the same value, and `maxResponseBytes` on an HTTP transport. The executor has no such option: it accepts results up to 1 MiB, so leave `limits.maxMessageBytes` at its default when the guard is the executor.

## Schemas

Arguments are validated against each tool's advertised JSON Schema with AJV, inside a bounded profile:

- The draft-07, 2019-09 and 2020-12 dialects; structural keywords; local `#/…` references without cycles.
- `format` and content keywords are annotations and do not validate, as in standard JSON Schema.
- `pattern` is accepted only when its matching time is bounded: at most 512 characters, no backreferences or lookaround, no quantified group that contains a quantifier or alternation, and one variable-length quantifier (two when anchored with `^`). A string over 4,096 characters never matches a pattern, and each validation has a fixed total budget for pattern work.
- External, dynamic or recursive references, `$id` and unknown keywords are refused.

A tool whose schema is outside the profile is skipped and listed in `connection.skipped`; it is never accepted with weaker validation. `compileBoundedSchema(schema)` exposes the same validator. These bounds limit work per message; they are not an operating-system CPU limit.

## HTTP transport

`createRestrictedMcpHttpTransport` wraps the SDK's Streamable HTTP transport with an exact HTTPS endpoint, no redirects, no automatic reconnection and a bounded response size. Plain HTTP is accepted only for `127.0.0.1` or `[::1]` with `allowInsecureLoopback: true`. An endpoint with embedded credentials or a fragment is refused.

The `fetch` you pass must enforce your DNS, IP and egress policy. Checking the endpoint URL does not stop an approved hostname from resolving to a private address; `createRestrictedFetch` from the executor does. The transport does not start servers, run a login flow or refresh tokens.

With your own transport, you own its endpoint rules, size limits before parsing, credentials and process isolation.

## Credentials

There are two ways to bind a connection to a verified credential.

**You verify the token.** Pass `authorize: () => assertVerifiedMcpClaims(claims, policy)` to the connection. `assertVerifiedMcpClaims` checks issuer, audience, subject, required scopes and expiry (in Unix seconds, with no clock-skew allowance) on claims that your own verifier has already authenticated. It never parses or verifies a token, so never pass claims that were only decoded. `authorize` must be synchronous. It runs at connection, discovery, preparation and dispatch, and a throw quarantines the connection.

**The package verifies a JWT access token.** `VerifiedMcpHttpSession.connect(options, accessToken)` verifies the token with `jose` against the issuer, key-set address, audience, subject and scopes you enrol, then owns the connection. Malformed options (an identifier, a binding or a limit) fail with `INVALID_CONFIGURATION` before any network call. It accepts `at+jwt` access tokens signed with RS256 (or ES256 if you list it), never ID tokens or keys chosen by the token. `replaceCredential(nextToken)` invalidates the session first, fetches the key set again and requires new approvals; a failed replacement does not restore the old token. `revoke()` and `close()` are final. The session closes if the server sends the token back in any message. The [verified credential guide](https://github.com/ShieldaAI/agent-guard/blob/main/docs/guides/verified-mcp-credentials.md) has the full contract.

Acquiring tokens, OAuth login and refresh flows, and checking opaque tokens stay with the host. `protectedValues` (up to 32 strings) makes any connection close when the server echoes one of them; a server that holds a secret can still transform or split it, so give credentials only to endpoints allowed to hold them.

## Inventory

`connection.inventory()` returns a frozen snapshot of what the connection has registered, without network requests or callbacks; it also works after close. It contains the host's server, principal and tenant IDs, an opaque `transportRef`, the session ID, the capture time, the state and, when `ready`, the name, kind and fingerprint of each operation. It never contains definitions, schemas, resource addresses, endpoints or credentials. Being listed does not mean an operation is approved.

Three counters describe change: `revision` advances on every state change, `authorizationEpoch` (also `connection.revision`) whenever approvals are invalidated, and `metadataRevision` only when the accepted definitions change. The format is described by the [inventory schema](https://github.com/ShieldaAI/agent-guard/blob/main/schemas/agent-guard-mcp-inventory-v1.schema.json); the [executor](https://github.com/ShieldaAI/agent-guard/blob/main/packages/executor/README.md) combines it with its own inventory.

## Errors

The package throws `McpBoundaryError` with a stable `code` and no server or request data. `McpBoundaryErrorCatalog[code]` gives the meaning of each code and what to do next.

```js
import { McpBoundaryErrorCatalog } from '@shieldaai/agent-guard-mcp';

console.log(McpBoundaryErrorCatalog.REGISTRY_CHANGED.action);
```

During `prepare()` and `execute()` the guard reports its own `GuardError` and keeps this package's code as `error.detail`: for example `RESOLUTION_FAILED` with detail `ARGUMENTS_INVALID` or `IDENTITY_DENIED`, and `TOOL_FAILED` with detail `MCP_OPERATION_FAILED` or `AUTHORIZATION_DENIED`. Check `isError` on a returned tool result yourself: an error reported inside a result is still a result and is charged normally.

## Use your own MCP client

`registerMcpTool` registers a single tool for a client you already own. It gives you the guard's checks for that tool, and none of the connection features above: no schema validation, no quarantine, no transport rules.

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
      // Call your MCP client here and pass the abort signal through.
      return { content: [{ type: 'text', text: `Report for ${request.name}` }] };
    },
  },
  resolve(args) {
    if (typeof args.id !== 'string') throw new Error('id must be a string');
    // Look up who owns the report in your own store.
    return { resourceId: args.id, tenantId: 'acme' };
  },
});
guard.approveTool(registered.name, registered.fingerprint);
```

With the official SDK client, `callTool` is `(request, { signal }) => sdk.callTool(request, { signal })` and `tool` is an entry of `(await sdk.listTools()).tools`. Grant tasks access to `registered.name` and use `guard.prepare()` and `guard.execute()`.

Every field of the definition is part of the fingerprint. Call `registerMcpTool` again when the server's tool list changes and approve the new fingerprint; earlier prepared calls then fail. `maxCost` reserves an upper bound and `measureCost(result)` may report the actual cost. Only the guard's JSON limits apply to results here: a result over `limits.maxJsonBytes` fails with `RESULT_INVALID` and revokes the task.

## What it does not do

- It does not sandbox the server or the transport. Run untrusted servers inside the executor's isolation.
- It does not authenticate a server. Approving a definition says nothing about the code behind it.
- It does not stop code that calls the MCP client directly, or that uses another connection.
- It does not obtain, refresh or store credentials.
- It does not enforce limits on the server. Cancelling a call asks the server to stop; the work may continue there.

See the [package guide](https://github.com/ShieldaAI/agent-guard/blob/main/docs/package-guide.md) and the [threat model](https://github.com/ShieldaAI/agent-guard/blob/main/docs/threat-model.md).

Apache-2.0. Copyright 2026 ShieldaAI contributors.
