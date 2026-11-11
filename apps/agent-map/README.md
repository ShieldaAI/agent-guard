# Agent Map viewer

A React/Cytoscape reference interface for the Agent Guard inventory service.
This app is a private workspace package; it is not published to npm or deployed by
the build. It contains no database driver or database credentials.

From the repository root:

```sh
npm run build --workspace @shieldaai/agent-map-viewer
npm test --workspace @shieldaai/agent-map-viewer
```

The build creates `dist/index.html`, `dist/app.js` and `dist/app.css`. Serve these
with the agent-map HTTP server or company gateway's explicit `viewerDirectory`
option. The browser checks the fixed same-origin `GET /auth/session` endpoint to
select the host's authentication mode. Missing, malformed or unavailable mode
responses show a retry state; they never silently enable another authentication
mode. An ordinary static file server supports the explicit synthetic demo only.

The loopback server advertises bearer mode. It sends fixed same-origin
`POST /v1/query` requests with an in-memory `agm_v1.…` reference credential and
omits cookies. It never persists the credential in browser storage, puts it in a
URL or sends it to an arbitrary endpoint. Reloading or disconnecting clears the
credential. A 401 or 403 also clears the credential and displayed inventory and cancels pending requests. The host service owns company, tenant and team access rules.

The company gateway advertises OIDC mode and supplies an expiring browser session
and CSRF value. The viewer sends same-origin cookies plus the CSRF header for
queries and the fixed `/auth/login` and `/auth/logout` routes. It accepts only a
validated HTTPS authorization URL from the login response before navigating to
the identity provider. OAuth access, refresh and ID tokens, scope claims, and
database credentials never enter viewer state. The only readable browser
authentication value is the ephemeral CSRF token; the session cookie is managed
by the host and is HttpOnly. No authentication values enter browser storage.

The company listener validates that the served certificate is currently valid,
matches its private key and covers the configured public hostname before startup.
An expired served certificate stops HTTP operations. Renew it before expiry and
restart the gateway; restart invalidates existing sessions. Use a verified HTTPS
probe for certificate renewal monitoring, in addition to testing company sign-in.

Known expiry, a 401/403 company query response, page hiding, or a back/forward
cache restore aborts pending work and clears displayed evidence. Authentication
denials take effect as soon as response headers arrive, even when the body is
empty, malformed, oversized or stalled. Returning to a
company page revalidates the session before loading evidence again. Delayed
responses from an ended session cannot enter a replacement workspace. Company
sign-out clears local evidence immediately and revokes the Agent Map browser
session. A failed sign-out shows an explicit retry state without silently
reconnecting. The identity provider's own session follows its company policy.

The viewer offers six views: Agent inventory, Owners, Resources, Changes, Discovery
and Health. Agent, owner and host-bound resource indexes use server-scoped pagination;
20 rows appear per page and exact totals remain attached to the active filters.
Owner links preserve the source as well as the owner ID. Environment suggestions
come from the current page; an exact environment can also be entered directly.

Discovery lists leads to agents the manifest does not declare: tasks and callers that
ran through an enrolled executor without a declared agent, and IAM roles and users of
enrolled AWS accounts that no declared agent names. Both are for all-teams readers; a
team-scoped reader sees one fixed note with no names and no counts. Unknown or stale
collection is shown as unknown, never as an empty list, and Health shows the
undeclared-activity count per source under the same rule.

An agent's Overview shows purpose, reported ownership, lifecycle, host assertion
provenance, deployments and paged tasks. Permissions separates declared grants,
registered tools, mapped policy candidates and a read-only exact task/tool/selector
explanation. Connections & resources shows host-bound resources, MCP connections,
execution bindings, observed identities, opaque credential references and named
relationships. Resource links open ownership, approved destinations, dependencies
and connected visible agents. Full relationship identifiers remain available in
expandable text details. The optional graph has an accessible node selector;
a graph limit does not prevent using the paged inventory sections.

Agent listings request `includeFlags` and show the "dangerous three" flag as a
text badge beside its colour: red **Exposed**, amber **Mitigated**, grey
**Unknown**; a known-absent leg shows no badge. A sidebar legend explains them and
the **Dangerous three flag** filter maps to the service's `flag` / `flagStatus`
arguments. The Overview reads `get_agent_access` once for its **Boundary flags**
and **Outside the guard** sections and the optional graph, so they always agree.
Boundary flags list one row per leg (private data, outside content, can send out)
with its state, reason, and task, tool and resource-binding identifiers, plus any
mitigation, notes and limitations. Outside the guard lists host-declared direct
paths per deployment (`found`, `none_declared` as the host's own claim, or
`unknown`) and, separately, each tool identity's scope with the extra buckets,
relationship, unresolved condition keys and truncation. These tables are the
accessible equivalent of the graph; "Show in graph" selects the matching node.

In the graph, declared direct paths (`G_DIRECT_ACCESS_FOR` and their declared
targets) are red dashed edges labelled "outside guard"; buckets a tool identity
reaches beyond its grants are drawn as candidate nodes behind amber dashed edges
labelled "tool identity reaches this"; the graph draws up to eight buckets per tool (300 edges in all) and
one "+N more" node for the rest, while the table lists them all. Guarded relationships stay solid. The
flagged agent node names its flag. **Outside guard only** hides everything except
those edges, their endpoints and enclosing boxes. Nodes sit in a tenant box (from
the snapshot receipt) and a team box (from the nearest agent's team); a node
equally near to several teams stays in the tenant box and provider nodes sit below,
outside every box. Edges that cross a box border are highlighted and say which
border they cross. The graph never zooms below a readable size; a larger
neighborhood opens at its top-left corner, pans, and **Fit graph** shows the whole.
Resources has a **Reachable outside guard** column (yes / none found / unknown),
and a resource's detail lists the declared paths and tool identities behind it.
Changes can filter to declared outside-guard paths, labelled **Declared**. None of
these statuses means access is safe or ruled out: only S3 identity policies and
host declarations are checked.

Agent changes and the Changes view compare authorized retained snapshots, with
before/after fields, relationship additions/removals and affected visible agents.
Paging applies to change details and their companion summaries. These are net
snapshot differences, not a complete intermediate event history. Approval events,
request-time decisions, backend receipts and external policy history are explicitly
not collected. Health shows independently timed component coverage and freshness.

Version 2 metadata is host-asserted evidence. A reported legacy owner ID is shown
separately from ownership status; it does not prove an assigned accountable owner.
Missing version 1 metadata remains unknown. Credential lifecycle, rotation and
expiry describe capture-time observations; opaque references are not usable
credentials. Resources covers exact host bindings: unbound selectors remain in
agent Permissions, and an empty resource index does not establish no access.

Search and filter changes show a loading state until the scoped query completes.
An unavailable query hides the previous list and offers **Refresh evidence** to
retry. Detail sections provide their own retry controls. Mobile navigation keeps
all six views available, and wide evidence tables scroll within labelled regions.
Each workspace dispatches at most two inventory reads concurrently. Navigation
cancels obsolete queued reads; already started reads keep their slot until they
settle and their obsolete results are discarded. Sign-out aborts the session and
rejects queued work. Queries are not automatically retried.

Policy candidates are always labeled with unknown access. A complete empty
result does not establish denial; unresolved boundaries, unsupported policies,
stale evidence and missing collection remain visible. History compares inventory
snapshots only and explicitly says policy history was not collected. Policy cards
and the accessible node selector provide text alternatives to the graph, and
condition keys are rendered as inert text.

Text is rendered by React or Cytoscape as inert labels; no imported HTML is
interpreted. Graphs reject invalid endpoints or excessive nodes/edges. Network
responses are bounded to 4 MiB and queries have a 12-second browser deadline;
the service applies its tighter authoritative limits. Colors, labels and dashed
lines distinguish uncertain associations and unavailable observations.

The login screen's **Open synthetic demo** is an explicit browser-only tour. The
page initially checks its host's sign-in mode; choosing the demo cancels a pending
check. Demo queries use local synthetic fixtures, make no inventory or identity
requests and keep a demo banner visible. They must not be used as evidence of an
actual executor or cloud connection.

The server's CSP must allow scripts from `self` and styles from `self` with inline
style attributes for Cytoscape's canvas sizing. No external fonts, images, scripts
or styles are fetched. The viewer is responsive and supports reduced motion.

## Verify the operator workflow across browsers

From the repository root on a supported POSIX host, run the built viewer against
a disposable loopback service. Browser tooling stays in a temporary directory.

```sh
npm run build
browser_tools=$(mktemp -d)
npm install --prefix "$browser_tools" --ignore-scripts --no-audit --no-fund playwright@1.63.0 axe-core@4.14.0
"$browser_tools/node_modules/.bin/playwright" install chromium firefox webkit
node apps/agent-map/check-browser.mjs "$browser_tools" artifacts/map/chromium chromium
node apps/agent-map/check-browser.mjs "$browser_tools" artifacts/map/firefox firefox
node apps/agent-map/check-browser.mjs "$browser_tools" artifacts/map/webkit webkit
```

The check opens the demo from the keyboard, opens the focused graph (with its
tenant/team boxes and outside-guard edges; label checks cover evidence nodes, not
the boxes that enclose them), inspects one resource, distinguishes
a missing grant from an unknown outcome, checks matching and empty lookups, and
compares snapshots. It also checks all five navigation views at a 375px viewport. A
real bearer session loads a synthetic version 2 projection through the actual
MapService: 25 agents, 23 owners, 25 resources, legacy unknown ownership, paged
changes, credential references and a 511-task agent whose graph is too large.
The walkthrough checks owner and resource navigation, before/after evidence,
large-agent task paging and mobile owner/resource/change tables. It checks a failed filter
request and successful retry, then receives a 401 response and verifies the
inventory disappears. The command exits with
an error on a failed assertion, an uncaught page error, or an axe WCAG 2/2.1 A/AA
violation in any sampled state. It also drives a real local signed-OIDC company
gateway, verifies session-revocation clearing and signs out. The browser accepts
the disposable fixture certificate only; the gateway verifies the configured
fixture CA. Inventory remains synthetic. Representative operators and
assistive-technology users still need to exercise the deployed workflow.
