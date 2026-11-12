# Connect to a remote MCP server with a verified access token

`VerifiedMcpHttpSession` connects the guard to a remote Model Context Protocol (MCP)
server over HTTPS. Before it connects, it checks that the access token your host supplies
was signed by your identity provider and was issued for that server.

## What you will achieve

- A connection to one fixed HTTPS MCP endpoint that opens only with a valid token.
- Tools from that server registered with the guard, waiting for your approval.
- A way to replace or revoke the token without leaving old access behind.

## Prerequisites

- Node.js 22.13 or later, with `@shieldaai/agent-guard`, `@shieldaai/agent-guard-mcp` and
  `@shieldaai/agent-guard-executor` installed.
- An MCP server reachable over HTTPS.
- An identity provider that issues signed JWT access tokens (type `at+jwt`) and publishes
  its signing keys at an HTTPS address.
- An access token, obtained by your host. This package does not log in, fetch tokens or
  renew them.

## Steps

### 1. Connect

```js
import { AgentGuard } from '@shieldaai/agent-guard';
import { createRestrictedFetch } from '@shieldaai/agent-guard-executor';
import { VerifiedMcpHttpSession } from '@shieldaai/agent-guard-mcp';

export async function connectReports(accessTokenFromHost) {
  const guard = new AgentGuard();
  const session = await VerifiedMcpHttpSession.connect(
    {
      guard,
      identity: { serverId: 'reports', principalId: 'report-reader', tenantId: 'company-a' },
      endpoint: 'https://tools.example.com/mcp',
      authorization: {
        issuer: 'https://identity.example.com',
        jwksUri: 'https://identity.example.com/keys',
        audience: 'https://tools.example.com/reports',
        subject: 'enrolled-idp-subject',
        requiredScopes: ['reports:read'],
        algorithms: ['RS256'],
      },
      fetch: createRestrictedFetch({
        allowedOrigins: ['https://identity.example.com', 'https://tools.example.com'],
        timeoutMs: 5000,
      }),
      tools: [
        {
          name: 'read_report',
          requiresApproval: true,
          resolve(args) {
            if (args.id !== 'report-123') throw new Error('Unknown report');
            return { resourceId: 'report-123', tenantId: 'company-a' };
          },
        },
      ],
    },
    accessTokenFromHost,
  );
  return { guard, session };
}
```

Replace the example addresses with your own. Every value in `authorization` comes from
your host's configuration. The model cannot supply a token, a key address, an audience or
any other part of it.

### 2. Approve the tools

A new connection registers its tools unapproved. Review them, then approve each one:

```js
for (const tool of session.registrations) guard.approveTool(tool.name, tool.fingerprint);
```

Tasks, grants and per-call approval work as for any other tool. See
[Tool permissions](tool-permissions.md).

### 3. Replace the token before it expires

```js
await session.replaceCredential(nextToken);
```

This closes the old connection first, then verifies the new token and connects again. The
tools must be approved again (step 2). If replacement fails, the session stays closed; it
never falls back to the old token. You may try again with a fresh token.

### 4. Revoke and close

```js
await session.revoke();
```

`revoke()` and `close()` are final. Close sessions before you close their executor.

## What you should see

- `connect` resolves, `session.status` is `ready`, and `session.registrations` lists
  `read_report`.
- With a token that fails any check, `connect` rejects with an `McpBoundaryError` whose
  `code` is `AUTHORIZATION_DENIED`. The error never contains the token or the provider's
  response.

To see it work without your own servers, run the tests. They start local HTTPS servers
with a temporary certificate authority:

```sh
npm run build
node --test packages/mcp/test/credentials.test.mjs packages/executor/test/network.test.mjs
```

## What is checked

A token is accepted only if all of these hold:

- It is signed with an allowed algorithm (`RS256` by default, `ES256` if you list it) by a
  key published at `jwksUri`.
- Its type is `at+jwt`. ID tokens are refused.
- It has `iss`, `sub`, `aud`, `exp`, `iat`, `jti` and `client_id`.
- `iss` and `sub` equal the configured issuer and subject, and `aud` includes the
  configured audience.
- It carries every scope in `requiredScopes`.
- It is not expired and its lifetime is within the limit. There is no clock-skew
  allowance.

Keys named inside the token itself are never used. The expiry is checked again on every
call, so an expired token stops working even if nobody replaced it.

`session.refresh()` reloads the server's tool list. It does not renew the token or fetch
keys again.

## Limits

| Setting | Default | Maximum |
| --- | --- | --- |
| `verificationTimeoutMs` | 5,000 | 30,000 |
| `maxJwksBytes` (size of the key set) | 256 KiB | 1 MiB |
| `maxTokenLifetimeSeconds` | 3,600 (one hour) | 86,400 (one day) |
| `maxResponseBytes` (one MCP response) | 1 MiB | 16 MiB |
| Token size | 16 KiB | fixed |
| Keys in the key set | 32 | fixed |

What this does not do:

- **It does not obtain tokens.** Login, OAuth flows, refresh tokens and opaque-token
  lookup are your host's job.
- **It does not prove the server enforces its own permissions.** It only proves the token
  is genuine and meant for that server.
- **Removing a key at the identity provider does not end a session.** Call `revoke()`,
  replace the token, or wait for it to expire.
- **Revoking does not undo a call that was already sent.** With the executor, such a call
  is held as an unknown outcome until an operator reconciles it.

## Use a private network or your own certificate authority

`createRestrictedFetch` allows only the origins you list, follows no redirects and
ignores proxy environment variables. By default it refuses private network addresses. To
reach an internal server signed by your own certificate authority:

```js
const network = createRestrictedFetch({
  allowedOrigins: ['https://internal.example.com'],
  allowPrivateOrigins: ['https://internal.example.com'],
  additionalCaByOrigin: { 'https://internal.example.com': enterpriseCaPem },
});
```

The extra certificate authority is trusted for that origin only. Certificate and hostname
checks stay on, and TLS 1.2 is the minimum.

| Extra certificate authorities | Limit |
| --- | --- |
| Per origin | 256 KiB and 16 certificates |
| Origins | 32 |
| Total | 1 MiB |

## What can go wrong

| Symptom | Cause | Fix |
| --- | --- | --- |
| `INVALID_CONFIGURATION` | The endpoint or key address is not HTTPS, a required value is missing, or a limit is above its maximum. | Check the options against step 1 and the limits table. |
| `AUTHORIZATION_DENIED` on connect | The token failed a check, or the key set could not be fetched in time. | Check the token's issuer, subject, audience, scopes, type and expiry against your configuration, and that both origins are in `allowedOrigins`. |
| `AUTHORIZATION_DENIED` on a call that used to work | The token expired or the session was revoked. | Call `replaceCredential` with a new token and approve the tools again. |
| `CREDENTIAL_REPLACEMENT_PENDING` | `replaceCredential` was called while another replacement was running. | Wait for the first one to finish. |
| `CONNECTION_UNAVAILABLE` | The session is closed, revoked, or a replacement failed. | Create a new session, or retry `replaceCredential` with a fresh token. |
| Tools are refused after a replacement | Every replacement registers the tools again, unapproved. | Repeat step 2. |

If you already have your own token verifier, `assertVerifiedMcpClaims` checks issuer,
audience, subject, scopes and time on claims you have verified. It does not verify a
signature.
