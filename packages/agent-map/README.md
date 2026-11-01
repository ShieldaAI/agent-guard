# Agent Guard reference map

Optional read-only reference service for the immutable Agent Guard projections
published by the [Cartography collector](../../integrations/cartography/README.md).
It supplies the same evidence to HTTP, MCP clients and the
[React/Cytoscape viewer](../../apps/agent-map/README.md). It never prepares or
executes an action. Declared grants and cloud associations are not effective
permission decisions.

Install the service with `npm install @shieldaai/agent-map@alpha`. It includes the
`agent-guard-map` and `agent-guard-map-identity` commands. Viewer assets and the
Python collector are separate repository components and are not bundled in this
npm package. The commands require host-owned configuration and credentials.

## Run the loopback bearer service

```sh
npm ci --ignore-scripts
npm run build
node packages/agent-map/dist/cli.js --config deployment/cartography/reference.example.json
```

Review the example's company, tenant and team identifiers, Neo4j address and
username before use. Provide `AGENT_MAP_NEO4J_PASSWORD` and
`AGENT_MAP_READER_TOKEN` through your host's secret environment. Generate the
reader token with `createMapToken()` and provision it through your trusted host;
do not commit it or include it in a URL. The launcher prints only its loopback URL
and mode. Open that URL and enter the reference token. The viewer keeps it in
memory until disconnect/reload and never sends it to a different origin. The
clearly labeled synthetic demo uses only browser-local fixture data.

The launcher requires nonblocking file-open support, as provided by the pilot's
POSIX hosts. Its configuration must resolve to a regular file of at most 128 KiB;
symlinks to regular files remain supported. It checks the opened descriptor and
limits bytes read even if the file grows. Named pipes and other nonregular inputs
fail startup with the same safe diagnostic. Native Windows is outside the
[pilot's supported host profile](../../deployment/cartography/RUNBOOK.md#prerequisites-and-layout).

Viewer asset hosting on both HTTP and HTTPS also requires nonblocking and
no-follow file-open support, as provided by the POSIX pilot hosts. The fixed
`index.html`, `app.js` and `app.css` entries must each be regular files of at most
4 MiB. The loader checks each opened descriptor, rejects a symlink replacing an
asset, and bounds reads even if the file grows. It captures the bytes at startup;
later path replacements do not change the served assets. Starting an API without
`viewerDirectory` does not require these file-open capabilities.

`agm_v1` reference credentials are independent of executor/task and observer
credentials. Each credential is mapped to an immutable `ReadScope` by the host:
`subject`, `companyId`, `tenantIds`, `teamIds`, `allTeams`. Neither HTTP nor MCP
arguments can override this scope. A team reader can see only agents explicitly
assigned to an allowed team and their attached evidence. `allTeams: true` is a
separate explicit grant, including unassigned/core inventory. It must not be
inferred from an empty team list. Restart with a revised credential registry to
rotate or revoke these bearer credentials.

The server binds `127.0.0.1` only and requires an exact Host header. Browser
requests must use its same origin. It provides no CORS, arbitrary Cypher,
database credentials, execution tools or administration routes. For company
browser access, use the separate HTTPS identity endpoint below. Do not expose
the loopback listener directly through an unchecked proxy.

Use a dedicated Neo4j reader account where database privileges are available.
The driver's READ session mode is not a privilege boundary. Neo4j Community
does not establish database-level team isolation; the service's fixed queries
and scope checks enforce its reference interface. The database remains a
trusted service accessible only to collector and query hosts. Remote database
connections require verified TLS (`neo4j+s` or `bolt+s`). Unencrypted connections
are accepted only with direct `bolt://` and a literal loopback address. Plaintext
`neo4j://` routing is rejected because advertised peers can leave loopback.

## Run the company HTTPS viewer

The separate `agent-guard-map-identity` launcher serves the viewer and scoped
queries over HTTPS with confidential OIDC sign-in. Follow the
[identity deployment guide](../../deployment/cartography/IDENTITY.md) to register
the provider, provision private configuration/TLS files and environment secrets,
and adapt [identity.example.json](../../deployment/cartography/identity.example.json).
After building and provisioning the private config:

```sh
node packages/agent-map/dist/identity-cli.js --config /absolute/private/identity.json
```

The installed package exposes the equivalent `agent-guard-map-identity` command.
The provider must support authorization code flow with S256 PKCE and RS256 ID
tokens. Each exact issuer `sub` has an explicit host-owned scope; provider groups
and browser arguments cannot grant access. The endpoint owns TLS, requires exact
Host/Origin, rejects forwarded identity/authorization headers and provides no
CORS. It does not wrap or reconfigure the loopback service.

The browser uses opaque Secure/HttpOnly cookies and CSRF-protected same-origin
POSTs. It receives no provider tokens or scope claims. Sessions last at most 15
minutes, capped by ID token expiry, and are not refreshed. Sign out ends the
local session only; the IdP SSO session may remain active. Bindings, secrets and
TLS files reload on restart, which invalidates all sessions. There is no
distributed session store or HA mode. A registered live company IdP and a
trusted-browser end-to-end check remain rollout gates; see the guide for their
status and the complete configuration/operational limits.

## Shared operations

On the loopback service, POST `/v1/query` with `Authorization: Bearer <reference-token>`, content type
`application/json` and `{ "operation": "list_agents", "args": {} }`.
Results contain `operation`, `observedAt`, `data` and an optional focused `graph`.
Source IDs are the graph source IDs returned by the service, not native source
names. Native agent/task IDs and returned stable entity IDs are accepted where
documented by the schemas. No pagination cursor exposes a broader scope.

| Operation | Arguments | Evidence |
| --- | --- | --- |
| `list_agents` | optional `sourceId`, `search`, `ownerId`, `environment`, `limit` | Scoped inventory for choosing an agent. |
| `get_agent_access` | `sourceId`, `agentId` | Focused deployments, tasks, grants, tools, bindings, MCP and cloud observations. |
| `explain_access` | `sourceId`, `taskId`, `tool`, `resourceId` | Visible delegation, declared matches, known blockers and explicit unknown checks. |
| `find_agents_with_access` | `resourceRef`, `action`; optional `sourceId`, `limit` | Potential candidates from exact host resource/action bindings; no wildcard or prefix expansion. |
| `get_changes` | `sourceId`; optional `since` | Net current/previous changes to currently authorized agents; explicit gaps. |
| `get_inventory_health` | optional `sourceId` | Visible capture times and independently stale or unavailable components. |

Snapshot generation time and component observation times are separate. Tasks and
tools retain their original capture times after host/MCP recomposition. MCP age
uses the oldest capture or observation among visible connections; recomposing a
cached observation does not refresh it. Missing observation times remain unknown
and stale for observed connections. Unavailable connections use the time their
failure was captured. Historical projections retain their own capture times.

On the loopback service, POST `/mcp` uses the official MCP SDK's stateless HTTP transport. The six tools
have the same arguments and use the same service as HTTP. Supply the reference
bearer in the client's HTTP headers. The host-only `createMapMcpServer(service,
scope)` factory also supports embedding; only trusted host code chooses scope.
There are no subscriptions, arbitrary resources or mutation methods. MCP tool
results contain the common JSON envelope as text; clients should treat all
imported names and identifiers as data, never instructions.

The company endpoint exposes the same `/v1/query` envelope with session cookies
and `X-CSRF-Token`, and deliberately has no `/mcp` route. Bearer/MCP credentials
and company browser sessions are separate authentication boundaries.

## Host API

### Current IAM policy evidence

The existing HTTP/MCP operations also expose the collector's optional IAM policy
candidate layer. `get_agent_access.data.policyEvidence` lists evidence for the
selected agent. `explain_access.data.externalEvidence.policyEvidence` selects the
exact task/tool/resource bindings; potential-access lookup further selects the
requested action. Each result identifies its task, deployment, execution binding,
resource binding and external endpoints by stable entity ID, with an independent
policy observation time, status, reason and `assessment: unknown`.

Only the three collected S3 mappings are supported. A complete record contains
zero or one candidate with mapping name, condition flag/key names and
`resourceScope: bucket_summary`. Empty candidates never prove denial. The original
host resource ARN, kind and scope remain on the binding graph; a bucket summary
does not authorize an exact object or prefix. Boundaries, unsupported policies,
missing collection, opt-out and stale/changed evidence remain explicit gaps.

The Neo4j reader derives pairs through a visible task's own deployment, declared
grant, resource binding and execution tool. It validates the exact provider
links, account ownership, scoped collection, membership and candidate provenance.
It rechecks the bounded raw evidence and source pointers before returning;
concurrent changes fail with a stable error instead of mixing observations.
The reader returns no raw policies, condition values, collection-wide hashes,
counts or unrelated provider neighbors. Generic Cartography `CAN_*` edges do not
fill missing owned evidence.

Policy age uses the tighter of the snapshot's enrolled cloud `maxAgeSeconds` and
the host's `Neo4jMapStoreOptions.policyMaxAgeSeconds` (default 7,200; maximum
86,400). A newer AWS capture makes old Guard provider joins unavailable until the
next successful Guard collection. `get_inventory_health` reports policy coverage
separately. `get_changes` returns `policyHistory: not_collected`: live candidates
are not attached to historical inventory snapshots or used to invent policy diffs.

The reader caps each request at 512 task/binding/action pairs and fails overflow
without returning partial evidence. Fixed read queries, row/byte limits, the
five-second transaction deadline and the existing response limits still apply.
Custom `MapStore` implementations may omit `MapProjection.policyEvidence`; supplied
records receive closed-shape and binding-path validation at the service boundary.
Complete evidence requires one owning agent and unambiguous tool/identity/binding
links, including unique task/grant and grant/selector pairs. Distinct valid grants
and resource selectors remain supported; ambiguous evidence may be reported as
unavailable with no candidates.
This metadata never changes executor admission.

Sources superseded through the host's [lifecycle command](../../deployment/cartography/SOURCE-LIFECYCLE.md)
are excluded from normal reads, including explicit source requests and history.
A read spanning supersession fails rather than returning its old view. The new
enrollment generation has its own source identity; supersession does not rewrite
the executor ledger or change agent permissions.

This self-contained example demonstrates the public contract without requiring
a database. For real inventory, replace the store with `createNeo4jMapStore` and
close it when the host shuts down.

```ts
import { MapService, validateReadScope, type MapStore } from '@shieldaai/agent-map';

const store: MapStore = { async read() { return { sources: [] }; } };
const service = new MapService(store);
const scope = validateReadScope({ subject: 'reader', companyId: 'example',
  tenantIds: ['engineering'], teamIds: ['platform'], allTeams: false });
const response = await service.query(scope, 'list_agents', {});
console.log(response.data);
```

To embed the company endpoint, load TLS material and secrets in trusted host
code. This self-contained function uses an empty store and is not invoked by the
example. Replace its paths, registered issuer/client and subject binding before
calling it; the host API requires an absolute viewer directory and loaded PEM
strings. The CLI adds the private-file checks described in the deployment guide.

```ts
import { readFile } from 'node:fs/promises';
import { MapService, startMapIdentityServer,
  type MapIdentityServer, type MapStore } from '@shieldaai/agent-map';

export async function startCompanyReference(clientSecret: string): Promise<MapIdentityServer> {
  const store: MapStore = { async read() { return { sources: [] }; } };
  return startMapIdentityServer({
    service: new MapService(store),
    publicOrigin: 'https://localhost:8788', listenHost: '127.0.0.1', port: 8788,
    tls: {
      key: await readFile('/absolute/private/tls/server-key.pem', 'utf8'),
      cert: await readFile('/absolute/private/tls/server-chain.pem', 'utf8'),
    },
    oidc: {
      issuer: 'https://login.example.invalid',
      clientId: 'replace-with-registered-client-id', clientSecret,
    },
    companyId: 'example-company',
    bindings: [{
      subject: 'replace-with-exact-idp-sub',
      scope: { subject: 'platform-reader', companyId: 'example-company',
        tenantIds: ['engineering'], teamIds: ['platform'], allTeams: false },
    }],
    viewerDirectory: '/absolute/path/to/agent-guard/apps/agent-map/dist',
  });
}
```

`bindings[].subject` is the exact IdP `sub`; `scope.subject` is a local alias and
can differ. The returned server exposes `replaceBindings`, `revokeSubject` and
`invalidateSessions` only to host code. Each invalidates all current sessions
and login transactions; revocation also removes that binding. Persist policy
changes in the host before restarting. Call `close()` during shutdown and close
any real Neo4j store. No HTTP administration endpoints are exposed.

Custom `MapStore` implementations are trusted adapters and must implement the
same visibility boundary as `Neo4jMapStore`; the service does not turn an
unscoped store into a scoped one. The included store filters all node/edge
queries before limits or materialization. Shared tools, principals, resources
and MCP connections do not reveal other teams' attached entities. Historical
membership is intersected with current authorized agent ownership, including
task ownership, so moving an agent/task between teams cannot expose its old
team's evidence. Hidden and nonexistent IDs return the same `MAP_NOT_FOUND`.
Team responses omit source-wide revision counters and hidden ancestor/family
identifiers. Explanations always retain a generic ancestor-scope uncertainty.

## Limits and semantics

Loopback defaults: 32 KiB HTTP request, 1 MiB service result (2 MiB transport ceiling),
500 focused nodes/1,000 edges, 64 sources and 2,000 nodes/5,000 edges per store
read, 5-second graph/service deadline, 10-second HTTP deadline, four concurrent
HTTP requests and 120 requests/minute per credential plus a global quota.
Streaming graph reads cap materialized nodes/edges at 4 MiB. Synchronous service
processing shares the query deadline and has a 200,000-unit work budget; potential
access evidence is limited to 1,000 entries and the cumulative response-byte
budget. Configuration has hard upper bounds. Oversized authorized inventories fail
closed instead of returning a misleading partial map. List operations return
up to 100 rows and explicitly indicate truncation.

The company endpoint has separate browser/provider limits, including a default
600 requests/minute per session and globally. Its complete defaults and hard
ceilings are in the [identity guide](../../deployment/cartography/IDENTITY.md).
The MapService/store limits and evidence semantics below apply to both endpoints.

The store uses fixed parameterized read-only templates in one transaction,
allowlisted properties and relationships, bounded graph paths, and a publication
pointer recheck. It never traverses into arbitrary provider policy data. A
pointer change fails the query for retry rather than mixing generations.
Current/previous comparisons are net differences, not an audit history; missing
or retired previous evidence is explicit. Collection times and global revision
changes alone are not entity changes. Health describes published inventory,
not collector process health. Source-wide publication timing is visible to
authorized readers of that source.

Blockers describe exported gates at capture/evaluation time. A result without
blockers remains `unknown`: live budgets, arguments, custom policy, approvals,
delegation outside scope and backend authorization still require evaluation.
Potential-access matches retain exact/prefix, static/dynamic, cloud freshness
and MCP lifecycle limitations. The graph is never used in executor admission.

## Validation

```sh
npm test
npm run test:pack
cd integrations/cartography
.venv/bin/python scripts/test-disposable-neo4j.py -- -q
```

JavaScript checks cover schemas, immutable scope, query bounds, safe HTTP,
official SDK HTTP/MCP equivalence, disposable HTTPS/OIDC exchange, cookie/CSRF
and revocation boundaries, private launcher files and viewer lifecycle behavior.
The packed-package check compiles both Host API examples and exercises the
installed identity boundary. Disposable Neo4j checks
exercise actual published graphs, cross-company/tenant/team isolation, shared
MCP metadata, moved ownership, hidden IDs, current/previous visibility and
absence of database mutations. Never run the integration suite against a
shared or production database.
