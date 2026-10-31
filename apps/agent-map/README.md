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
credential. The host service owns company, tenant and team access rules.

The company gateway advertises OIDC mode and supplies an expiring browser session
and CSRF value. The viewer sends same-origin cookies plus the CSRF header for
queries and the fixed `/auth/login` and `/auth/logout` routes. It accepts only a
validated HTTPS authorization URL from the login response before navigating to
the identity provider. OAuth access, refresh and ID tokens, scope claims, and
database credentials never enter viewer state. The only readable browser
authentication value is the ephemeral CSRF token; the session cookie is managed
by the host and is HttpOnly. No authentication values enter browser storage.

Known expiry, a 401/403 company query response, page hiding, or a back/forward
cache restore aborts pending work and clears displayed evidence. Authentication
denials take effect as soon as response headers arrive, even when the body is
empty, malformed, oversized or stalled. Returning to a
company page revalidates the session before loading evidence again. Delayed
responses from an ended session cannot enter a replacement workspace. Company
sign-out clears local evidence immediately and revokes the Agent Map browser
session. A failed sign-out shows an explicit retry state without silently
reconnecting. The identity provider's own session follows its company policy.

The viewer offers:

- Agent search with owner/environment filters and a focused evidence graph.
- An accessible node selector and evidence panel alongside the canvas.
- Read-only task/tool/resource explanations with unknown checks retained.
- Exact resource/action lookup labeled as potential access.
- Current/previous snapshot comparisons with retention gaps.
- Visible-source freshness and component coverage.
- Current IAM policy candidate cards and dashed graph edges tied to exact task,
  execution and resource bindings; timestamps, conditions and scope stay visible.

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
