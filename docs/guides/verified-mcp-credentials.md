# Verified remote MCP credentials

`VerifiedMcpHttpSession` joins cryptographic access-token verification, a fixed HTTPS MCP endpoint and the existing managed connection. A trusted host obtains a token, enrolls the endpoint and authorization policy, then creates a session. Models cannot supply credentials, key URLs, resource audiences, trust anchors or policy. This is a deliberately restricted JWT access-token profile; the separate Agent Map browser OIDC login remains unchanged.

```ts
import { AgentGuard } from '@shieldaai/agent-guard';
import { createRestrictedFetch } from '@shieldaai/agent-guard-executor';
import { VerifiedMcpHttpSession } from '@shieldaai/agent-guard-mcp';

export async function connectReports(accessTokenFromHost: string) {
  const guard = new AgentGuard();
  const session = await VerifiedMcpHttpSession.connect({
    guard,
    identity: { serverId: 'reports', principalId: 'report-reader', tenantId: 'company-a' },
    endpoint: 'https://tools.example.com/mcp',
    authorization: {
      issuer: 'https://identity.example.com',
      jwksUri: 'https://identity.example.com/keys',
      audience: 'https://tools.example.com/reports',
      subject: 'enrolled-idp-subject', requiredScopes: ['reports:read'],
      algorithms: ['RS256'],
    },
    fetch: createRestrictedFetch({
      allowedOrigins: ['https://identity.example.com', 'https://tools.example.com'],
      timeoutMs: 5000,
    }),
    tools: [{ name: 'read_report', requiresApproval: true,
      resolve(args) {
        if (args.id !== 'report-123') throw new Error('Unknown enrolled report');
        return { resourceId: 'report-123', tenantId: 'company-a' };
      } }],
  }, accessTokenFromHost);
  // The authenticated host now reviews registrations before approving their fingerprints.
  // Tasks, resource grants and per-call approval still use the guard or durable executor.
  return { guard, session };
}
```

The host explicitly enrolls the endpoint-to-audience relationship. A resource audience can differ from the MCP endpoint. The JWT subject can differ from the host's local principal alias, but both mappings must be trusted. Token claims never supply tenant grants. The low-level transport and `assertVerifiedMcpClaims` remain available for applications that already have another maintained verifier; neither independently verifies an arbitrary token.

## Verification and credential replacement

The implementation uses pinned `jose` 6.2.13 to verify the signature against an exact HTTPS JWKS URI. It accepts signed `at+jwt` or `application/at+jwt` access tokens, with an explicit algorithm allowlist (`RS256` by default, optionally `ES256`). It requires `iss`, `sub`, `aud`, `exp`, `iat`, `jti` and `client_id`, exact issuer/subject, the enrolled resource audience, and every required space-delimited scope. ID tokens, token-selected key locations, embedded signing keys, unknown keys, unsigned/symmetric algorithms, expired/not-yet-valid tokens and excessive lifetimes fail closed. There is no expiry clock-skew allowance.

These choices follow the [JWT access-token profile](https://www.rfc-editor.org/rfc/rfc9068.html) and use the maintained library's [remote JWKS verifier](https://github.com/panva/jose/blob/main/docs/jwks/remote/functions/createRemoteJWKSet.md). The application still chooses its issuer, trusted keys, resource binding and grants. JWT validation does not prove that the remote service enforces its own authorization.

`replaceCredential(nextToken)` closes the old managed connection and invalidates its registrations **before** asynchronous verification. Each replacement fetches a fresh key set, creates a new connection/session and requires renewed metadata approval and any per-call approval. Failure leaves the session unavailable; it never restores the old token. Overlapping replacements reject with `CREDENTIAL_REPLACEMENT_PENDING`. Host code may explicitly retry a failed replacement with a newly obtained credential.

`refresh()` only reloads MCP metadata under the current credential. It does not renew tokens or fetch keys. Removing a JWKS key does not automatically revoke an existing verified session: the host must call `revoke()`, replace the credential, or wait for token expiry. `revoke()` and `close()` are terminal and abort pending verification/requests. They cannot be reversed with replacement. Close sessions before closing their executor.

Every guarded dispatch rechecks the verified expiry and host revocation. A monotonic deadline also prevents a backward wall-clock change from extending the accepted lifetime. Credentials remain in private transport state; the public session exposes status, optional session ID/inventory and registrations, with no token, claims or raw SDK client getter. Verification failures expose stable error codes, never provider bodies or token contents.

Revoking a dispatched call does not prove the remote effect stopped. The durable executor retains `UNKNOWN` reservations and forbids replay until trusted backend evidence supports reconciliation. Do not reconcile from a local timeout or a server's unverified assertion. Deadline/abort races settle the session API even if a supplied fetch ignores cancellation; the supplied network implementation must still own and bound its sockets and resources. A late result cannot publish old authority or overwrite newer registrations.

## Network trust and limits

Use the executor's `createRestrictedFetch`, or an equivalent trusted implementation enforcing policy at the actual socket. `additionalCaByOrigin` adds operator-approved PEM trust anchors only to their exact allowed HTTPS origins. Node's bundled roots remain available, certificate and hostname checks remain mandatory, and TLS 1.2 is the minimum. Trust additions do not allow private networks: separately enroll an exact private origin in `allowPrivateOrigins` when needed. No global trust/environment changes are required.

```js
const network = createRestrictedFetch({
  allowedOrigins: ['https://internal.example.com'],
  allowPrivateOrigins: ['https://internal.example.com'],
  additionalCaByOrigin: { 'https://internal.example.com': enterpriseCaPem },
});
```

Additional CA bundles are bounded to 256 KiB and 16 certificates per origin, 32 origins and 1 MiB total. Invalid configuration is rejected before a request. Public-only origins reject private or mixed public/private DNS answers, including on a later connection. DNS resolution occurs once through the socket's checked lookup; late resolution after timeout/cancellation cannot dispatch credentials. The network adapter never follows redirects or uses proxy environment variables.

The session's verification deadline defaults to 5 seconds (maximum 30 seconds), JWKS bytes to 256 KiB (maximum 1 MiB), token lifetime to one hour (maximum one day), and MCP response bytes to 1 MiB (maximum 16 MiB). Tokens are limited to 16 KiB and key sets to 32 keys. JWKS requests contain no bearer token, reject redirects, and have bounded bodies before parsing. Existing managed MCP time/message/registry limits still apply. The verification timer covers old-session closure and verification; MCP initialization then uses the managed connection's request deadline.

## Reproduce the evidence

```sh
npm run build
node --test packages/mcp/test/credentials.test.mjs packages/executor/test/network.test.mjs
```

The fixture creates a private temporary CA and real HTTPS JWKS/MCP servers. It verifies permitted read/write effects, exact bearer replacement, renewed review, rejected JWT/TLS profiles, removed-key rejection on replacement, redirects, response/deadline bounds, expiry, revocation and cleanup. Separate late-completion tests exercise stalled host fetches and prove old initialization cannot overwrite a newer registry. The installed-package consumer repeats a protected HTTPS workflow using packed artifacts and independently created signed tokens. No company credentials, remote providers or system/browser CA installation are involved.

DNS regressions use an isolated child process that substitutes resolver answers while the production socket lookup performs enforcement. This proves the adapter's checked-resolution path, not an assessment of live DNS infrastructure. TLS tests use normal certificate/hostname verification with scoped temporary trust. Native platform acceptance requires these tests without skips alongside the existing Docker boundary tests.

Token acquisition, OAuth discovery/authorization-code or refresh-token flows, opaque-token introspection, provider revocation events, company IdP configuration and production TLS/key rotation remain host integration work. Browser-trusted company rollout, native Linux/Windows evidence and VM recovery retain their separate gates. The local fixtures do not certify those deployments.

## Recorded validation, 5 November 2026

The full `npm run check` passed all 800 tests with zero skips on Node 26.12.0, including the real Docker tests, followed by clean installed-package consumers. The new installed consumer independently signs access tokens with Node crypto and exercises HTTPS read/write approvals, key rotation, credential replacement, stale approvals, revocation and trace privacy against packed packages.

The macOS arm64 platform gate passed all 33 selected tests, including every required Docker, HTTPS credential, certificate/hostname and DNS test. The [saved local summary](../validation/verified-mcp-credentials-2026-11-05.json) records the exact host, images, required test names and current source/test hashes. All 22 credential/network/platform-verifier tests also passed on Node 22.13.0. Independent review addressed abort-only deadlines, late registry publication and post-revocation response handling. A positive TLS fixture deadline has sufficient headroom for parallel CI; intentional timeout failures remain separately covered.
