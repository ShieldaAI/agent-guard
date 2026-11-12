# @shieldaai/agent-map

A read-only inventory service for AI agents. It answers questions such as "which agents
exist and who owns them", "what was this agent granted", "which agents could touch this
resource" and "what changed since the last snapshot", over HTTP, over MCP and for a
browser viewer. It reads a Neo4j graph and never prepares, approves or executes anything.

**Experimental.** The package shares the Agent Guard version number, but its API and
graph model are not covered by the 1.x compatibility promise and may change in a minor
release.

What it shows is evidence: declared grants, host observations and cloud policy
candidates. None of it is a decision that access is allowed, and a missing fact is
reported as `unknown`, never as "none".

## Before you start

You need three things. Only the first is on npm.

1. **Node.js 22.13 or later** on a POSIX host (Linux or macOS). The launchers need
   non-blocking, no-follow file opens; native Windows is not supported.
2. **Neo4j 5.23 or later**, reachable over verified TLS (`neo4j+s://` or `bolt+s://`), or
   over plain `bolt://` on a literal loopback address only.
3. **A graph filled by the Agent Guard Cartography collector.** The collector is a Python
   program in the Agent Guard repository and is **not published to npm**. It reads an
   executor's inventory and a host manifest and publishes immutable snapshots that this
   service reads. Follow the
   [collector README](https://github.com/ShieldaAI/agent-guard/blob/main/integrations/cartography/README.md) and the
   [setup guide](https://github.com/ShieldaAI/agent-guard/blob/main/docs/guides/agent-cartography.md).

Without a collector-filled graph the service starts and answers, with nothing in it. The
[quick start](#quick-start) below needs neither Neo4j nor the collector: it runs the
service over an in-memory store so you can see the interface first.

The map lists only agents that a person declared in a host manifest. It does not scan
infrastructure, code, networks or identity providers. See
[how agents get onto the map](https://github.com/ShieldaAI/agent-guard/blob/main/docs/guides/agent-cartography.md#how-agents-get-onto-the-map).

## Capacity

Sized for roughly **150 declared agents per reader** with the default limits, and
roughly **800** with the store's read limits raised to their maximum (`maxNodes: 10000`,
`maxEdges: 25000`, `maxBytes: 16777216`; see [Limits](#limits)). These are estimates,
not measurements: the node limit divided by about a dozen graph nodes per agent. An
agent with more tasks, grants or bindings counts for more.

Every operation answers from one bounded read of the graph the reader may see. Paging
pages that read's result; it does not reach past the read. A larger fleet fails with
`MAP_LIMIT_EXCEEDED` instead of returning part of it. `list_agents` reads fewer nodes per
agent and so reaches further; `get_changes` reads two snapshots within the same limits
and reaches about half as far. [Limits](#limits) gives the estimate for each kind of read
and says what was tested.

Values above the default limits are accepted, but they have only been exercised against
a fake database driver in this package's tests, never against Neo4j. The 5-second
transaction deadline does not grow with them. Before you rely on raised limits, run your
largest reads against your own database and check that they finish in time.

## Quick start

```sh
mkdir map-try && cd map-try
npm init -y
npm install @shieldaai/agent-map
```

Save this as `try.mjs` and run `node try.mjs`. It starts the loopback service over an
in-memory store with one agent, asks it one question over HTTP and stops.

```js
import { MapService, createMapToken, startMapServer } from '@shieldaai/agent-map';

// A store is anything with `read(scope, request)`. This one holds one declared agent in memory.
const projection = {
  id: 'projection-1',
  snapshotId: 'snapshot-1',
  generatedAt: new Date().toISOString(),
  status: 'published',
  nodes: [
    {
      id: 'node-1',
      entityId: 'agent:support',
      label: 'GuardAgent',
      sourceId: 'demo',
      projectionId: 'projection-1',
      properties: { agent_id: 'support-assistant', name: 'Support assistant', team_id: 'support' },
    },
  ],
  edges: [],
  coverage: { tasks: { status: 'complete' } },
};
const store = {
  async read() {
    return {
      sources: [
        { id: 'demo', tenantId: 'engineering', sourceId: 'demo', profile: 'host', current: projection, previous: null },
      ],
    };
  },
};

const token = createMapToken();
const server = await startMapServer({
  service: new MapService(store),
  credentials: [
    {
      token,
      scope: { subject: 'me', companyId: 'example', tenantIds: ['engineering'], teamIds: [], allTeams: true },
    },
  ],
});
const response = await fetch(`${server.url}/v1/query`, {
  method: 'POST',
  headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
  body: JSON.stringify({ operation: 'list_agents', args: {} }),
});
const { data } = await response.json();
console.log(data.agents.map(agent => `${agent.name} (${agent.lifecycleState}, ${agent.ownershipStatus})`));
await server.close();
```

It prints `[ 'Support assistant (unknown, unknown)' ]`: the agent is listed, and the
lifecycle and ownership nobody declared read `unknown`.

### Run it against Neo4j

Write a configuration file (see [Configuration](#configuration)), keep the secrets in the
environment, and start the launcher:

```json
{
  "neo4j": {
    "uri": "bolt://127.0.0.1:7687",
    "username": "agent_map_reader",
    "passwordEnv": "AGENT_MAP_NEO4J_PASSWORD"
  },
  "credentials": [
    {
      "tokenEnv": "AGENT_MAP_READER_TOKEN",
      "scope": {
        "subject": "platform-reader",
        "companyId": "example-company",
        "tenantIds": ["engineering"],
        "teamIds": ["platform"],
        "allTeams": false
      }
    }
  ]
}
```

```sh
export AGENT_MAP_NEO4J_PASSWORD='...'
export AGENT_MAP_READER_TOKEN="$(node -e "import('@shieldaai/agent-map').then(m => console.log(m.createMapToken()))")"
npx agent-guard-map --config ./map.json
```

The launcher prints `{"url":"http://127.0.0.1:8789","mode":"read-only"}` and serves
`POST /v1/query` and `POST /mcp` on that loopback address. Send the token as
`Authorization: Bearer <token>`:

```sh
curl -s http://127.0.0.1:8789/v1/query \
  -H "Authorization: Bearer $AGENT_MAP_READER_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"operation":"list_agents","args":{}}'
```

Neither launcher connects to Neo4j at startup: an unreachable or misconfigured database
shows as `MAP_UNAVAILABLE` on queries. For browser access by company staff, use the
second launcher, `agent-guard-map-identity`, which serves HTTPS with OIDC sign-in; see
[Company sign-in](#company-sign-in).

## Operations

Twelve read-only operations, the same over HTTP (`POST /v1/query` with
`{ "operation": "...", "args": {...} }`) and as MCP tools (`POST /mcp` on the loopback
service). A result has `operation`, `observedAt`, `data` and, for `get_agent_access`
only, an optional `graph`.

"Any reader" means any credential or signed-in user, within its own scope: a team reader
sees only agents assigned to its teams and what is attached to them.

| Operation | What it answers | Who can call it |
| --- | --- | --- |
| `list_agents` | Which declared agents exist, with owner, team, lifecycle and environments. Filters: `search`, `sourceId`, `ownerId`, `teamId`, `environment`, `ownershipStatus`, `lifecycleState`, `flag`, `flagStatus`; `includeFlags` adds each agent's flag. | Any reader |
| `get_agent_access` | One agent's tasks, declared grants, bindings, MCP connections, IAM policy evidence, [boundary flags](#boundary-flags) and access [outside the guard](#outside-the-guard), with a graph when it is small enough. Needs `sourceId`, `agentId`. | Any reader |
| `get_agent_inventory` | One paged `section` of one agent's inventory (`overview`, `owners`, `deployments`, `tasks`, `permissions`, `resources`, `connections`, `credentials`, `relationships`, `tools`, `bindings`, `identities`, `policies`) and the size of every section in `counts`. A size or `total` of `null` means the section was not evaluated. Needs `sourceId`, `agentId`. | Any reader |
| `explain_access` | For one `taskId`, `tool` and `resourceId` in a `sourceId`: which declared grants match, which known blockers apply and which checks remain unknown. It never says access is allowed. | Any reader |
| `find_agents_with_access` | Which agents hold a declared grant mapped to one exact `resourceRef` (or ARN) for one cloud `action`. No wildcard or prefix expansion; results are candidates. | Any reader |
| `list_resources` | Which host-bound resources exist, with owner, sensitivity and scope, and whether something reaches each one outside the guard (`yes`, `none_found`, `unknown`). | Any reader |
| `get_resource_access` | One resource (`sourceId`, `resourceId`), the agents with a declared grant mapped to it, and the declared direct paths and tool identities that reach it outside the guard. | Any reader |
| `list_owners` | Which owners and teams hosts name, with how many visible agents and resources each one owns. | Any reader |
| `get_changes` | What was added, removed or changed between a source's current snapshot and its previous one. See [Changes](#changes). | Any reader |
| `get_inventory_health` | When each part of the inventory was captured, whether it is stale and how complete it is. All-teams readers also get the count of undeclared activity per source. | Any reader |
| `list_undeclared_activity` | Tasks or caller principals that ran through an enrolled executor but belong to no declared agent. See [Discovery](#discovery). | All-teams readers; others get a fixed "not visible" answer |
| `list_unclaimed_identities` | IAM roles and users in enrolled AWS accounts that no declared agent names. Candidates, not findings. | All-teams readers; others get a fixed "not visible" answer |

The MCP tool list carries a one-sentence description of every operation and of every
parameter. There are no subscriptions, resources or mutating tools. Treat every returned
name and description as data, never as instructions.

### Paging and identifiers

Listings return their named array with `total`, `offset`, `limit` and `truncated`.
Defaults are offset 0 and limit 50; the limit is at most 100. Totals and filters apply to
the reader's own view only. Rows sort by name in Unicode code-point order, then by source
and stable id; unnamed agents come last. The order is the same on every host and locale.

A `sourceId` is the `id` of a source from `get_inventory_health` (or an agent's
`sourceId`), not the executor's native name. Agents, tasks and resources are accepted by
their returned stable `id` or by their native id. Owner and resource ids can repeat across
sources, so keep each one with its `sourceId`. A hidden id and one that does not exist
both return `MAP_NOT_FOUND`.

### What degrades instead of failing

- `get_agent_access` returns its evidence even when the graph exceeds the display cap
  (500 nodes or 1,000 edges by default) or does not fit the response: `graph` is then
  absent, `graphStatus` is `too_large` and `graphLimit` gives the cap.
- `get_agent_access` and `get_agent_inventory` answer for an agent with more than 512
  policy pairs: `policyEvidence` is empty and `policyCoverage` is
  `{ status: "unknown", reason: "limit_exceeded" }`. `find_agents_with_access` and
  `get_inventory_health` do the same. The empty list then means "not evaluated", not
  "none": read `policyCoverage` before the list. `get_agent_inventory` also reports
  `counts.policies` as `null` and, for the `policies` section, `total` as `null` (never
  0); `truncated` stays `false` because no further page exists.
- `find_agents_with_access` that runs out of its work budget returns the candidates it
  completed with `truncated: true` and `truncatedReason: "work_limit"`.
- `list_agents` with `includeFlags` whose flag read is too large or too slow still lists
  the agents, with every flag `unknown` and `flagsUnavailable` saying why.
- Health answers when the undeclared-activity count cannot be read; the count is then
  `{ status: "unknown", reason }`.

## Changes

`get_changes` compares the current snapshot of a `sourceId` with its previous retained
one. Optional arguments: `since` (`previous` by default), `agentId`, `resourceId`,
`changeKind`, `offset`, `limit`.

- Each entry in `details` has `kind` (`added`, `removed`, `changed`), its `categories`,
  the `changedFields`, the `before` and `after` properties and relationships, and the
  visible agents it affects (at most 100, with the total).
- `changeKind` is `all`, `permissions`, `ownership`, `bindings`, `outside_guard` or
  `inventory`. `outside_guard` covers declared direct paths and a deployment's declaration
  status, and carries `evidenceKind: declared`. `inventory` is every change in no other
  category, such as a name, a purpose or a lifecycle state.
- With an explicit `offset` or `limit`, `changeSummaryScope` is `page`: the `changes`
  summary, relationship changes and affected agents describe that page. Without paging
  they describe every retained change and `details` holds the first 50.
- `coverageGap: true` means there is no previous snapshot to compare with.
- A renamed agent appears under its current name. A change of display name is not a
  relationship change. Capture times alone are not changes.

These are net differences between two snapshots, not an event log. They do not show that
effective access was gained or lost, and policy history is not collected
(`policyHistory: "not_collected"`).

## Discovery

The map lists declared agents only. Two operations point at what a manifest may be
missing. They never create an agent and never grant or block anything. Both are for
readers with `allTeams: true`, because what they list belongs to no team. A team reader
gets `{ visibility: "all_teams_required", status: "not_visible", note }` and nothing
else: no names, no counts, and the same answer whether or not anything would be listed.

**Undeclared activity.** A task is undeclared when no manifest task binding assigns it to
a deployment of a declared agent; a caller principal is undeclared when none of its tasks
is assigned.

- `get_inventory_health` adds `undeclaredActivity` to each source:
  `{ status, tasks, tasksIsMinimum, principals, principalsIsMinimum, manifest }`. `status`
  is `complete`, or `partial` when counting stopped at 10,000. `manifest: "not_collected"`
  marks a source enrolled without a manifest, where every task counts.
- `list_undeclared_activity` (`sourceId`, optional `kind` of `tasks` or `principals`)
  returns `items`, `total`, `totalIsMinimum`, paging fields, the same `counts` and a
  snapshot `receipt`. A task item has `taskId`, `principalId`, `delegated`, `derived`,
  `revoked`, `parentDeclared` and up to 32 `tools`. `parentDeclared: true` usually means a
  sub-task that only lacks its own binding.
- Only activity through an enrolled executor is seen. An agent that does not use the
  guard leaves nothing here.

**Unclaimed cloud identities.** `list_unclaimed_identities` reads the AWS collections in
the graph (see the [AWS guide](https://github.com/ShieldaAI/agent-guard/blob/main/deployment/cartography/AWS.md)).

- `identities` are IAM roles and users whose exact ARN no declared execution binding
  names. Each has `arn`, `kind`, `name`, `path`, `tenantId`, `partition`, `accountId` and
  `candidate: true`. Most roles are not agents; these are candidates to review.
- `accounts` has one entry per enrolled account, `complete` or `unknown` with a `reason`
  (`stale`, `collection_invalid`, `changed`, `limit_exceeded`, `claims_limit_exceeded`).
  An unknown account lists none of its identities.
- `status` is `complete`, `partial` or `unknown`. With `unknown`, `total` is `null` and
  the list is empty; unknown is never an empty list presented as "none".
- Role assumption, instance profiles and federation are not followed. At most 64
  collections, 50,000 identities per account and 10,000 declared ARNs are compared.

## Boundary flags

`get_agent_access` returns `boundaryFlags` with one flag, `dangerous_three`: whether one
of the agent's live tasks can read private data, read outside content and send data out.

| Status | Meaning |
| --- | --- |
| `exposed` | All three apply and a declared sending tool runs without approval. |
| `mitigated` | All three apply, but every possible sender needs approval or is refused after outside content. |
| `unknown` | The declarations do not settle at least one of the three. |
| `absent` | At least one of the three is known not to apply. |

- Each of the three (`privateData`, `outsideContent`, `externalSend`) is `present`,
  `absent` or `unknown`, with evidence naming the task, tool and resource binding.
- An agent's status is that of its worst live task, ranked exposed, unknown, mitigated,
  absent, so a mitigated task never hides one that might be exposed.
- Only an explicit `readsUntrusted: false` or `sendsExternal: false` rules a tool out.
  Older inventories, unregistered tools, delegation ancestors outside the reader's scope
  and chains deeper than 16 ancestors make the affected part `unknown`; `notes` says
  which.
- A task counts as live only if no delegation ancestor or handoff source is revoked and
  none has expired.
- `list_agents` adds the status with `includeFlags: true` (one extra read of the returned
  page) and filters with `flag: "dangerous_three"` (everything but `absent`) or
  `flagStatus`.

The flag is declared evidence, not proof that data can leave.

## Outside the guard

`get_agent_access` also returns `outsideGuard`:

- `directAccess`: per deployment, the paths the host declared that act without the guard
  (a shell, a database client, an SDK). The status is `found`, `none_declared` (the host's
  own claim, not a check) or `unknown` (the host has not said).
- `identityScope`: for each tool that runs under a static AWS identity, the collected S3
  buckets that identity has a policy candidate on but the tool's grants do not bind
  (`broader_than_grants`), or `matches_grants`, or `unknown` with a reason. A record lists
  at most 100 extra buckets; a cut list is marked `truncated` and keeps its status.

`list_resources` and `get_resource_access` report the same evidence from the resource's
side. Only S3 identity policies and host declarations are checked. Bucket policies, SCPs
and permission boundaries are not, so the buckets are candidates, and `none_found` is not
proof that no path exists.

## IAM policy evidence

Where the collector has AWS evidence, `get_agent_access`, `get_agent_inventory`
(`policies` section), `explain_access` and `find_agents_with_access` return
`policyEvidence`: one record per task, binding and action, with `status` (`complete`,
`unavailable`, `not_collected`), a `reason`, an observation time and `candidates`, an
array with at most one entry.

- Three S3 mappings are supported: `s3:GetObject`, `s3:PutObject`, `s3:ListBucket`.
- A candidate is bucket-level evidence (`resourceScope: "bucket_summary"`) with a
  condition flag and the names of its condition keys. It does not authorize an exact
  object or prefix, and an empty result does not prove denial.
- No raw policy, condition value or unrelated provider data is returned.
- Evidence older than the snapshot's enrolled age limit, capped by `policyMaxAgeSeconds`
  (two hours by default), is reported `stale`, not used.
- At most 512 task/binding/action pairs are evaluated per read, each operation narrowed to
  what it shows. `explain_access` fails with `MAP_LIMIT_EXCEEDED` past that; the others
  answer with coverage `unknown` (see above).

`assessment` is always `unknown`: this metadata never changes what the executor admits.

## Scopes and privacy rules

Every caller has a `ReadScope` chosen by the host: `subject`, `companyId`, `tenantIds`,
`teamIds`, `allTeams`. Request arguments cannot change it.

- **Team readers** see only agents explicitly assigned to one of their teams, and what is
  attached to those agents. Shared tools, principals, resources and MCP connections do not
  reveal other teams' entities.
- **All-teams readers** (`allTeams: true`) also see unassigned inventory and the discovery
  operations. It is an explicit grant and is never inferred from an empty team list.
- A hidden id and an id that does not exist return the same `MAP_NOT_FOUND`.
- For a team reader, a declared direct path whose target is outside its scope is listed
  without the target; identity-scope buckets that no visible binding maps are mentioned in a
  note, never named or counted; and explanations always keep a generic "ancestors outside your scope"
  uncertainty.
- History is filtered by current ownership, so moving an agent between teams does not
  expose its old team's evidence.
- Only allowlisted properties leave the store. Credential entries are opaque references
  with lifecycle metadata; no secret, token or raw policy is stored or returned.
- Error responses carry a code and nothing else: no path, name, query or value.

The service provides no arbitrary Cypher, no CORS, no administration route and no way to
write. The Neo4j driver's read mode is not a privilege boundary, and Neo4j Community has
no per-team isolation: use a dedicated reader account, and treat the database as a
trusted service reachable only by the collector and this service.

## Company sign-in

`agent-guard-map-identity` serves the viewer and `POST /v1/query` over HTTPS with OIDC
sign-in (authorization code flow with S256 PKCE and RS256 ID tokens). It has no `/mcp`
route.

```sh
npx agent-guard-map-identity --config /absolute/private/identity.json
```

- Each exact issuer `sub` is bound to a scope in the configuration. Provider groups and
  browser arguments cannot grant access.
- The browser gets an opaque Secure, HttpOnly session cookie and a CSRF value. It
  receives no provider token. Sessions last at most 15 minutes, capped by the ID token's
  expiry, and are not refreshed. Sign-out ends the map session only.
- The endpoint owns TLS, requires the exact Host and Origin, rejects forwarded identity
  headers and reads only its own two `__Host-agm_*` cookies.
- The certificate must match its key, be valid and cover the public host name. Once it
  expires, requests are refused: renew and restart before then. A restart reloads
  bindings and secrets and ends every session. There is no shared session store.
- An identity provider clock up to five seconds ahead is tolerated
  (`oidc.clockToleranceSeconds`, 0 to 60). Expiry is never extended.

Registration, file permissions and the full option list are in the
[identity guide](https://github.com/ShieldaAI/agent-guard/blob/main/deployment/cartography/IDENTITY.md), with an
[example configuration](https://github.com/ShieldaAI/agent-guard/blob/main/deployment/cartography/identity.example.json).

## Configuration

### `agent-guard-map --config FILE`

The file is strict JSON (no comments, no duplicate keys), at most 128 KiB, a regular file
owned by the service user or root and not writable by group or others. This launcher
follows a symbolic link at the configuration path (a mounted configuration is often one)
and applies the checks to the file it leads to; the file may be readable by others and
may have more than one hard link, because it holds names of environment variables and
scopes, not secrets. The company launcher below is stricter.

| Key | Required | Meaning |
| --- | --- | --- |
| `neo4j.uri` | yes | `neo4j+s://`, `bolt+s://`, or `bolt://` on a loopback address. Plain `neo4j://` is refused. |
| `neo4j.username` | yes | The reader account. |
| `neo4j.passwordEnv` | yes | Name of the environment variable that holds the password. |
| `neo4j.database` | no | Database name; `neo4j` by default. |
| `neo4j.maxNodes`, `neo4j.maxEdges`, `neo4j.maxBytes` | no | Per-read limits; see [Limits](#limits). |
| `credentials[]` | yes | 1 to 128 entries of `{ "tokenEnv", "scope" }`. `tokenEnv` names the environment variable that holds an `agm_v1.` token from `createMapToken()`; `scope` is the reader's `ReadScope`. |
| `port` | no | Loopback port; 8789 by default. |
| `viewerDirectory` | no | Directory with the viewer's `index.html`, `app.js`, `demo.js` and `app.css` (all four required, each at most 4 MiB, same ownership rule, no symbolic links). The viewer is built from the Agent Guard repository; it is not in this package. |

The server binds `127.0.0.1` only and requires an exact Host header. Do not expose it
through a proxy that does not check both. To rotate or revoke a token, change the
environment and restart.

`--help` prints the usage and `--version` the package version. A startup failure prints
one line, `MAP_START_FAILED <code>: <hint>` (followed by a usage line when an argument is
wrong), and exits with status 1; see [Error codes](#error-codes).

### `agent-guard-map-identity --config FILE`

The same `neo4j` block, plus `publicOrigin`, `tls` (`keyFile`, `certFile`), `oidc`
(`issuer`, `clientId`, `clientSecretEnv`, and optional `clientAuthMethod`,
`endpointOrigins`, `caFile`, `requestTimeoutMs`, `maxResponseBytes`,
`clockToleranceSeconds`), `companyId` and `bindings` (`subject`, `scope`). Optional:
`listenHost`, `port`, `viewerDirectory`, `sessionTtlMs`, `loginTtlMs`, `maxSessions`,
`maxLoginTransactions`, `requestTimeoutMs`, `maxRequestBytes`, `maxResponseBytes`,
`maxConcurrentRequests`, `rateLimit`. Unlike the reference launcher, this one does not
follow symbolic links and does not accept files owned by root: the configuration, the
TLS key and certificate and the optional CA file must each be a regular file owned by
the service user, with one hard link, not a symbolic link and not writable by group or
others. The configuration and the TLS key must also be private to the service user (no
group or other access). Viewer assets keep the rule given for `viewerDirectory` above.
Details are in the [identity guide](https://github.com/ShieldaAI/agent-guard/blob/main/deployment/cartography/IDENTITY.md).

### Options in code

| Where | Option | Default | Range |
| --- | --- | --- | --- |
| `MapService` | `maxResponseBytes` | 1 MiB | 128 bytes to 8 MiB |
| | `maxGraphNodes` / `maxGraphEdges` | 500 / 1,000 | up to 2,000 / 5,000 |
| | `queryTimeoutMs` | 5,000 | 10 to 10,000 |
| | `staleAfterSeconds` | 900 | 1 to 86,400 |
| `createNeo4jMapStore` | `timeoutMs` | 5,000 | up to 5,000 |
| | `maxSources` | 64 | up to 64 |
| | `maxNodes` / `maxEdges` / `maxBytes` | 2,000 / 5,000 / 4 MiB | up to 10,000 / 25,000 / 16 MiB (above the defaults: not tested against Neo4j, see [Limits](#limits)) |
| | `policyMaxAgeSeconds` | 7,200 | up to 86,400 |
| `startMapServer` | `port` | any free port | 0 to 65,535 |
| | `maxRequestBytes` | 32 KiB | 128 bytes to 64 KiB |
| | `maxResponseBytes` | 2 MiB | 128 bytes to 2 MiB |
| | `requestTimeoutMs` | 10,000 | 10 to 30,000 |
| | `maxConcurrentRequests` | 4 | 1 to 32 |
| | `rateLimit` | 120 requests per 60 s per credential | up to 10,000 per window of 10 ms to 60 s |

A value outside its range is `MAP_CONFIG_INVALID`.

## Use it from code

The service takes any `MapStore`. This example needs no database; for real inventory use
`createNeo4jMapStore` and close it when the host shuts down.

```ts
import { MapService, validateReadScope, type MapStore } from '@shieldaai/agent-map';

const store: MapStore = {
  async read() {
    return { sources: [] };
  },
};
const service = new MapService(store);
const scope = validateReadScope({
  subject: 'reader',
  companyId: 'example',
  tenantIds: ['engineering'],
  teamIds: ['platform'],
  allTeams: false,
});
const response = await service.query(scope, 'list_agents', {});
console.log(response.data);
```

A custom `MapStore` is a trusted adapter: it must apply the reader's scope itself. The
service validates what it is given (allowlisted properties, the shape and binding path of
policy evidence) but does not turn an unscoped store into a scoped one. `MapReadRequest`
tells a store what a read needs (`summary`, `owners`, `policy`, `boundary` and so on); a
store that ignores it and returns the whole scoped graph is still correct.

To embed the company endpoint, load the TLS material and secrets in trusted host code.
The host API takes loaded PEM strings and an absolute viewer directory; the launcher adds
the private-file checks.

```ts
import { readFile } from 'node:fs/promises';
import { MapService, startMapIdentityServer, type MapIdentityServer, type MapStore } from '@shieldaai/agent-map';

export async function startCompanyReference(clientSecret: string): Promise<MapIdentityServer> {
  const store: MapStore = {
    async read() {
      return { sources: [] };
    },
  };
  return startMapIdentityServer({
    service: new MapService(store),
    publicOrigin: 'https://localhost:8788',
    listenHost: '127.0.0.1',
    port: 8788,
    tls: {
      key: await readFile('/absolute/private/tls/server-key.pem', 'utf8'),
      cert: await readFile('/absolute/private/tls/server-chain.pem', 'utf8'),
    },
    oidc: {
      issuer: 'https://login.example.invalid',
      clientId: 'replace-with-registered-client-id',
      clientSecret,
    },
    companyId: 'example-company',
    bindings: [
      {
        subject: 'replace-with-exact-idp-sub',
        scope: {
          subject: 'platform-reader',
          companyId: 'example-company',
          tenantIds: ['engineering'],
          teamIds: ['platform'],
          allTeams: false,
        },
      },
    ],
    viewerDirectory: '/absolute/path/to/viewer/dist',
  });
}
```

`bindings[].subject` is the exact `sub` from the identity provider; `scope.subject` is a
local alias. The returned server offers `replaceBindings`, `revokeSubject` and
`invalidateSessions` to host code only; each ends every current session. Call `close()`
on shutdown.

Other exports: `startMapServer` and `createMapToken` (the loopback service),
`createMapMcpServer(service, scope)` (an MCP server for a scope that trusted host code
chooses), `validateReadScope`, `MAP_OPERATIONS`, `MAP_INPUT_SCHEMAS` and
`validateQueryArguments`.

`@shieldaai/agent-map/service` exports the service alone, without the Neo4j store or the
servers: `MapService`, `MAP_OPERATIONS`, `MAP_INPUT_SCHEMAS`, `validateQueryArguments`
and four names that only this subpath exports, not the package root:
`MAP_OPERATION_DESCRIPTIONS` (one sentence per operation) and the closed vocabularies
`MAP_LABELS`, `MAP_RELATIONSHIPS` and `MAP_PROPERTIES`. The subpath does not load
`neo4j-driver`, `openid-client` or an HTTP server, but it is not free of Node built-ins:
it imports `node:buffer`, and through `@shieldaai/agent-guard` also `node:crypto` and
`node:util/types`. A browser bundle must supply stand-ins for those three, as the viewer
build does.

## Limits

| Limit | Default | Notes |
| --- | --- | --- |
| Nodes, edges and bytes per store read | 2,000 / 5,000 / 4 MiB | Across all of a reader's sources, and both snapshots for `get_changes`. Raise with `maxNodes`, `maxEdges`, `maxBytes`, up to 10,000 / 25,000 / 16 MiB; see the note on raised limits below. |
| Sources per read | 64 | |
| Store transaction and service deadline | 5 s each | Does not move when the read limits are raised. |
| Service work per query | 200,000 units | One budget for the main answer. Four optional parts each count against a separate budget of the same size, so running out there degrades that part instead of failing the answer: the candidate search of `find_agents_with_access`, the page flags of `list_agents` with `includeFlags`, the flag of `get_agent_access`, and outside-guard reach in `list_resources` and `get_resource_access`. |
| Response size | 1 MiB (service), 2 MiB (HTTP) | Past it, optional detail goes first (identity-scope bucket lists, then the graph); then the answer fails. |
| Graph in `get_agent_access` | 500 nodes / 1,000 edges | Past it the evidence is returned without the graph. |
| Rows per page | 50, at most 100 | |
| Policy pairs per read | 512 | |
| Candidates in `find_agents_with_access` | 50, at most 100; 1,000 evidence entries | |
| HTTP request body | 32 KiB | |
| HTTP request deadline | 10 s | |
| Concurrent HTTP requests / store reads | 4 / 8 | |
| Requests per credential | 120 per minute | Plus a global quota. The company endpoint allows 600 per session. |
| Company session | 15 minutes | Never refreshed. |

How many agents each kind of read reaches. These are estimates, not measurements: the
node limit (2,000 by default, 10,000 at the maximum) divided by the nodes that read loads
per agent, for a fleet with about a dozen graph nodes per agent (one or two deployments
and tasks, their grants, bindings, tools and identities). Your figure is your own node
count per agent, and the edge and byte limits can be reached first.

| Read | Loads | Estimate, default limits | Estimate, maximum limits |
| --- | --- | --- | --- |
| `list_agents`, also with `includeFlags` | Agents, deployments, owners | about 900 | about 4,500 |
| `list_owners`, all-teams reader | Agents, resource bindings, owners | about 1,900 | about 9,000 |
| `list_owners`, team reader | The above plus what decides which bindings are visible | about 250 | about 1,200 |
| `list_resources`, `get_resource_access`, `find_agents_with_access`, `explain_access`, `get_inventory_health`, `list_agents` with `flag` or `flagStatus` | The whole visible graph | about 150 | about 800 |
| `get_changes` | The whole visible graph of two snapshots | about 75 | about 400 |
| `get_agent_access`, `get_agent_inventory` | The selected agent's own neighborhood | not bound by fleet size | not bound by fleet size |
| `list_undeclared_activity`, `list_unclaimed_identities` | Counts and one page, read in the database | not bound by fleet size | not bound by fleet size |

What was tested: `test/capacity.test.mjs` runs the listing operations (`list_agents`,
`list_owners`, `list_resources`, `get_resource_access`, `find_agents_with_access`,
`get_inventory_health`) for an all-teams reader over a synthetic fleet of 800 agents in a
graph of about 9,000 nodes and 8,800 relationships, with the limits at their maximum.
That test uses a fake database driver. It shows that the store's bookkeeping and the
service's work budget hold at that size; it says nothing about how long Neo4j takes.
`get_resource_access` walks every visible agent, so the service work budget can stop it
before the node limit does.

Raised limits: values above the defaults are accepted up to the maximum, but no read
above the defaults has been run against a Neo4j database. The transaction deadline stays
at 5 seconds and records are fetched 32 at a time whatever the limits are, so a read of
10,000 nodes and 25,000 relationships makes about a thousand round trips inside that
deadline. A host that raises the limits should load its largest expected fleet into its
own database and confirm that `list_resources`, `get_inventory_health`,
`find_agents_with_access` and `get_changes` answer without `MAP_TIMEOUT`, for a team
reader as well as an all-teams reader.

Raise the three store limits together: a read holds up to `maxBytes` in memory and up to
eight reads run at once.

Other things to know:

- A read is one transaction over fixed, parameterized queries. If a new snapshot is
  published while it runs, the read fails with `MAP_UNAVAILABLE` rather than mix two
  snapshots; retry it.
- Snapshot time and component capture times are separate. Recomposing a snapshot does not
  make an old MCP or cloud observation fresh.
- Health describes the published inventory, not whether the collector process is running.
- A source retired through the host's
  [lifecycle command](https://github.com/ShieldaAI/agent-guard/blob/main/deployment/cartography/SOURCE-LIFECYCLE.md) is no longer read.
- A result of `explain_access` without blockers is still `unknown`: live budgets, request
  arguments, custom policy, approvals and backend authorization are not evaluated here.

## Error codes

An HTTP error is a JSON body `{ "error": "<code>" }` and nothing else. An MCP tool error
carries the same code. `service.query` and `store.read` throw a `MapQueryError` whose
`code` is one of these.

| Code | HTTP status | Meaning |
| --- | --- | --- |
| `MAP_REQUEST_INVALID` | 400 | The request is not valid JSON, has an unknown operation or argument, or a wrong value. Also sent with status 417 for an `Expect` header other than `100-continue`. |
| `MAP_UNAUTHENTICATED` | 401 | The bearer token is missing or not accepted. |
| `MAP_SESSION_REQUIRED` | 401 | The company session is missing, ended or not signed in. |
| `MAP_IDENTITY_INVALID` | 401 | Company sign-in could not be completed. |
| `MAP_REQUEST_DENIED` | 403 | Wrong host, origin, route, method or CSRF value. |
| `MAP_SCOPE_INVALID` | 403 | The scope given to the service is not a valid `ReadScope`. |
| `MAP_NOT_FOUND` | 404 | The source, agent, task or resource does not exist or is outside the reader's scope. |
| `MAP_TIMEOUT` | 408 or 504 | 408: the request did not arrive in time. 504: the request arrived, and the read (or, at sign-in, the identity provider) ran out of time. |
| `MAP_LIMIT_EXCEEDED` | 413 | The answer needs more than one bounded read, or more work or bytes than allowed. Narrow the request. |
| `MAP_REQUEST_TOO_LARGE` | 413 | The request body is over the limit. |
| `MAP_RESPONSE_TOO_LARGE` | 413 | The response is over the transport limit. |
| `MAP_RATE_LIMITED` | 429 | Too many requests; wait and retry. |
| `MAP_BUSY` | 503 | Too many requests in progress, or the server is stopping. |
| `MAP_UNAVAILABLE` | 503 | The database is unreachable, returned something malformed, or a snapshot was published during the read. |
| `MAP_IDENTITY_UNAVAILABLE` | 503 | The identity provider did not answer. |
| `MAP_CONFIG_INVALID` | none | Thrown by constructors and launchers for an option out of range or a file that fails its checks. |

Startup failures print `MAP_START_FAILED <code>: <hint>` with one of
`MAP_ARGUMENT_INVALID` (followed by a usage line), `MAP_CONFIG_NOT_FOUND`,
`MAP_CONFIG_UNREADABLE`, `MAP_CONFIG_INVALID`, `MAP_CREDENTIAL_REQUIRED` (an environment
variable the configuration names is empty), `MAP_SCOPE_INVALID`, `MAP_LISTEN_FAILED`,
`MAP_IDENTITY_INVALID`, `MAP_IDENTITY_UNAVAILABLE` or `MAP_UNAVAILABLE` (a required
service or capability is unavailable). Any other failure prints
`MAP_START_FAILED: unexpected failure during startup.` with no code. No path, name, value
or secret is printed.

## Related

- [Viewer](https://github.com/ShieldaAI/agent-guard/blob/main/apps/agent-map/README.md): the browser interface for this service.
- [Operations runbook](https://github.com/ShieldaAI/agent-guard/blob/main/deployment/cartography/RUNBOOK.md): collecting, publishing and
  serving in one place.
- [Package guide](https://github.com/ShieldaAI/agent-guard/blob/main/docs/package-guide.md): which Agent Guard package does what.
- [Risk map](https://github.com/ShieldaAI/agent-guard/blob/main/docs/risks.md): which risks the map helps with, and which it does not.

## License

Apache-2.0. See [LICENSE](./LICENSE).
