# Company identity for the reference map

The company browser endpoint serves the Agent Map viewer over HTTPS and maps
verified OpenID Connect identities to host-owned `ReadScope` bindings. It calls
the same read-only `MapService` used by the loopback reference service. It does
not change executor admission or make the map an authorization decision engine.

Use the separate `agent-guard-map-identity` launcher for this endpoint. The
existing `agent-guard-map` launcher remains loopback-only and uses independent
`agm_v1` bearer credentials for HTTP, MCP and its local viewer. Company sessions
cannot authenticate to that listener; the company endpoint rejects bearer
authorization and has no `/mcp` route. See the [reference package](../../packages/agent-map/README.md)
and [operations runbook](RUNBOOK.md) for the shared queries and collector setup.

## Register the application and choose its origin

1. Choose one exact HTTPS origin, such as `https://agent-map.company.example`.
   `publicOrigin` must contain only the origin: no trailing slash, path, query,
   fragment or credentials. Provide a matching certificate and chain trusted by
   the intended browsers. The launcher terminates TLS itself, with TLS 1.2 as
   the minimum. `listenHost` is a literal bind IP; it defaults to `127.0.0.1`.
   Choose an explicit reachable interface and firewall policy for a company host.
2. Register a confidential OIDC web client with an exact redirect URI of
   `<publicOrigin>/auth/callback`. For the local example that is
   `https://localhost:8788/auth/callback`. Use authorization code flow, PKCE
   `S256`, RS256-signed ID tokens and either `client_secret_basic` (default) or
   explicitly configured `client_secret_post`. Discovery metadata must advertise
   S256 and RS256 and support the chosen client authentication method. If the
   authentication-method list is omitted, only the Basic default is accepted.
   The callback uses a top-level GET with query parameters; `form_post` and JARM
   responses are not supported.
3. Set `oidc.issuer` to the provider's exact HTTPS issuer identifier, including
   any path or trailing slash it defines. It must equal discovery's `issuer`;
   do not enter a discovery-document URL. Discovery, authorization, token and
   JWKS endpoints must use HTTPS. The issuer's origin is allowed automatically.
   If provider endpoints use other origins, list only those additional exact
   origins in `oidc.endpointOrigins`, for example
   `["https://tokens.company.example"]`. Entries cannot include paths, trailing
   slashes, duplicates or the already allowed issuer origin; at most eight
   additional origins are accepted. Discovered endpoint URLs cannot contain
   credentials, query strings or fragments. Server-to-provider HTTP redirects
   are rejected.
4. Obtain each intended reader's exact stable OIDC `sub` through the trusted
   identity administration process. Add an explicit binding before sign-in.
   Email, name, groups and other provider claims do not create access grants.

The server checks the literal Host header against `publicOrigin`. Browser POSTs
must have its exact Origin. There is no CORS or trusted proxy identity mode.
`Forwarded`, common `X-Forwarded-*` headers, rewrite headers and authorization
headers are rejected. Preserve end-to-end TLS and the original Host if using
network forwarding; an ordinary TLS-terminating reverse-proxy setup is not an
implemented deployment mode. Do not expose the separate loopback bearer service
through an unchecked proxy.

## Prepare private configuration and launch

Use Node.js 22.13 or newer on a POSIX host. From the repository root:

```sh
npm ci --ignore-scripts
npm run build
install -d -m 700 "$HOME/.config/agent-guard-map/tls"
install -m 600 deployment/cartography/identity.example.json "$HOME/.config/agent-guard-map/identity.json"
```

Edit that private copy of [identity.example.json](identity.example.json):

- Replace the issuer, client ID and binding subject placeholders. Match company,
  tenant and team identifiers to the published inventory. The sample issuer is
  intentionally nonfunctional until replaced with your registered provider.
- Set `publicOrigin`, `listenHost` and `port` for the intended host. The sample
  stays on `https://localhost:8788` and requires a browser-trusted localhost
  certificate. A remote deployment needs its own DNS name and matching trusted
  certificate; do not bypass certificate validation.
- Provision `tls/server-key.pem` and `tls/server-chain.pem` in the private
  configuration directory. Set the key to mode `0600` or `0400` and the public
  certificate chain to `0644` or stricter. Keep the private key outside the repo.
- Set `viewerDirectory` to the absolute path of the built
  `apps/agent-map/dist` directory. The three fixed viewer assets are loaded at
  startup. The installed npm package does not bundle the viewer assets.
- Configure a dedicated Neo4j reader account where privileges are available.
  Remote connections require verified `neo4j+s` or `bolt+s`; plaintext is allowed
  only for direct `bolt://` with a literal loopback address. The database remains
  a trusted service; READ session mode does not establish database privileges.

Provision `AGENT_MAP_NEO4J_PASSWORD` and `AGENT_MAP_OIDC_CLIENT_SECRET` through the
host's existing secret manager or protected process environment. The JSON stores
only environment variable names. Do not put secrets in arguments, URLs, browser
storage, committed files or logs. Start from the repository root:

```sh
node packages/agent-map/dist/identity-cli.js --config "$HOME/.config/agent-guard-map/identity.json"
```

When installed as a package, the equivalent command is
`agent-guard-map-identity --config /absolute/private/identity.json`. Startup
performs provider discovery and prints only the configured URL and
`oidc-read-only` mode. Open that URL and choose **Sign in with company account**.
The synthetic demo remains an explicit browser-local option. A bootstrap or
provider failure never silently switches the viewer to bearer authentication.

All relative file paths, including `viewerDirectory`, resolve against the
identity configuration file's directory. The CLI requires current-user-owned
regular files with one hard link, rejects symbolic-link file entries and
group/world-writable inputs, and bounds reads. Config and private key files
must have no group/other permissions. The config limit is 128 KiB; key,
certificate and optional issuer CA files are each limited to 256 KiB. Protect
parent directories as well: leaf-file checks do not establish trust in every
ancestor directory. Native Windows is not supported by this private-file loader.
The host API accepts already loaded PEM strings, so an embedding host must
enforce its own secret and file-handling policy.

For a provider using an enterprise CA, optionally set `oidc.caFile` to a PEM
certificate bundle in the private config. It is subject to the public-certificate
file checks and accepts up to 16 certificates. This adds trust to Node's bundled
roots for this issuer client's HTTPS requests only; it does not replace those
roots or change OS/browser trust. It does not make the viewer certificate trusted
in a browser. Never disable TLS verification to make a provider or viewer work.

## Host-owned visibility and revocation

`bindings[].subject` matches the verified OIDC `sub` exactly. Its nested
`scope.subject` is a local reader alias and may differ from that `sub`:

```json
{
  "subject": "idp-stable-subject",
  "scope": {
    "subject": "platform-reader",
    "companyId": "example-company",
    "tenantIds": ["engineering"],
    "teamIds": ["platform"],
    "allTeams": false
  }
}
```

Every scope must match the endpoint's `companyId`. Subject bindings are unique,
with a maximum of 1,024 entries. An empty registry denies every sign-in.
`allTeams: true` is an explicit grant that includes unassigned/core inventory;
it is never inferred from an empty list. A team reader requires at least one
team, and every scope requires at least one tenant. Browser query arguments
cannot replace or widen the scope. There is no self-enrollment, claim-based
role mapping, user administration route or automatic directory synchronization.

The CLI reads configuration once. To change bindings, rotate secrets or reload
TLS material, update the private files/environment and restart the process.
Restart invalidates all browser sessions and unfinished logins. Disabling an
IdP account alone does not immediately revoke an already issued local session;
remove its binding and restart to apply immediate host revocation.

An embedding host can call `replaceBindings(nextBindings)`,
`revokeSubject(idpSubject)` or `invalidateSessions()` on the result of
`startMapIdentityServer`. These are host APIs, not HTTP routes. Each invalidates
**all** current sessions and login transactions; `revokeSubject` also removes
the selected binding. Invalid replacement bindings are rejected before replacing
the registry. The host must persist policy changes itself; the CLI has no live
reload or persistence API. `close()` stops the listener and invalidates sessions.

## Browser session and resource bounds

Only `openid` is requested. The confidential server verifies issuer, audience,
signature, state, nonce, PKCE and token times using `openid-client`; provider
tokens stay on the server. It does not request userinfo or use provider claims
to expand visibility. The browser receives only session mode, authentication
status, a CSRF token and expiry, never provider tokens or host scope claims.

`GET /auth/session` creates an anonymous session when necessary. Login and
logout are `POST /auth/login` and `POST /auth/logout` with `{}` JSON; queries
remain `POST /v1/query` with the normal operation/args envelope. All three POST
routes require same-origin cookies, exact Origin and the current
`X-CSRF-Token`. The viewer manages these headers. `/auth/callback` is the sole
cross-site navigation route and redirects only to `/` or `/?auth_error=1`.

Opaque `__Host-agm_session` and `__Host-agm_login` cookies are Secure, HttpOnly,
SameSite=Lax and Path=/, with no Domain. Session IDs are hashed in server memory.
Login transactions are single-use and tied to the initiating session. Sessions
are rotated after authentication. Responses use no-store and restrictive browser
headers. Sign out deletes the local session and cookies; it does **not** sign
the user out of the IdP or revoke provider tokens. A subsequent sign-in may
reuse the provider's existing SSO session.

| Setting | Default | Maximum |
| --- | --- | --- |
| `sessionTtlMs` | 900,000 (15 minutes) | 900,000 |
| `loginTtlMs` | 300,000 (5 minutes) | 300,000 |
| `maxSessions` (including anonymous sessions) | 1,024 | 4,096 |
| `maxLoginTransactions` | 128 | 1,024 |
| `requestTimeoutMs` | 10,000 | 30,000 |
| `maxRequestBytes` | 32 KiB | 64 KiB |
| `maxResponseBytes` | 2 MiB | 2 MiB |
| `maxConcurrentRequests` | 4 | 32 |
| `rateLimit.maxRequests` | 600 | 10,000 |
| `rateLimit.windowMs` | 60,000 | 60,000 |
| `oidc.requestTimeoutMs` | 5,000 | 10,000 |
| `oidc.maxResponseBytes` | 256 KiB | 1 MiB |

The rate limit applies per session and to a shared global bucket; it includes
the browser routes, not only queries. Provider request bounds cover discovery,
token/JWKS requests, DNS and response bodies. The shared MapService has its own
result, query and graph limits, which can reject a request before the transport
ceiling. The viewer separately bounds authentication replies to 16 KiB.

Authenticated expiry is the earlier of the configured session lifetime and ID
token expiry. Activity does not renew it. Login expiry also cannot outlive its
initiating session. Both wall-clock and monotonic deadlines are enforced.
The viewer clears evidence and aborts requests on expiry, authorization failure,
tab hiding or restored browser history, and revalidates when visible again.
Logout failure clears local evidence and requires an explicit retry.

There is no refresh-token flow, distributed session store, HA coordination,
back-channel logout or persistent session recovery. Run one instance for this
milestone. Restart signs everyone out; host invalidation does not coordinate
across independently started instances.

## Validation and rollout gate

Automated tests use a disposable HTTPS identity provider and local test trust
scoped to its client. They exercise code exchange, signed-token verification,
scope mapping, CSRF, session/revocation races, request bounds and the packed
launcher. Viewer transport/lifecycle tests and a UI-only browser fixture cover
company-session rendering and local sign-out. The attempted disposable HTTPS
browser check was blocked by its untrusted test certificate; it did not complete
a real browser OIDC flow and no global trust settings were changed.

The 30 October 2026 local checks passed 582 JavaScript tests with no skips,
474 Python unit tests and 65 disposable-Neo4j integration tests. The clean
installed-package check compiled the public declarations/README examples and
performed a real local HTTPS login and scoped read using the packed package.
See the [milestone record](../../docs/cartography-integration-plan.md#company-identity-and-https-milestone)
for the scope of this evidence. Test fixtures require `openssl` on PATH; they
generate short-lived keys/certificates in a private temporary directory and
remove them during cleanup. They never install a system or browser CA.

Before company rollout, validate the registered live IdP and deployed viewer in
a browser that trusts both TLS chains: successful and denied sign-in, exact
team visibility, expiry, local sign-out, subject revocation/restart and denial
of an unbound subject. Confirm the intended DNS/interface/firewall deployment,
private-file ownership, secret rotation procedure and read-only database access.
Record this evidence in the [runbook](RUNBOOK.md). Live company IdP registration
and a trusted-browser end-to-end check remain rollout gates, not completed
deployment claims. Startup errors are deliberately reported as
`MAP_START_FAILED`; diagnose configuration, file permissions, endpoint metadata
and certificate trust without logging provider responses or secrets.
