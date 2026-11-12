# Agent Map viewer

A browser interface for the [`@shieldaai/agent-map`](../../packages/agent-map/README.md)
inventory service. It shows which AI agents people declared, what each one was granted,
what changed between snapshots, and which agents combine private data, outside content
and the ability to send data out. It is read-only: it never grants or blocks anything.

The viewer is a private workspace package (React, Cytoscape, built with esbuild). It is not
published to npm, holds no database driver and no database credentials.

## Try it

From the repository root:

```sh
npm ci
npm run build
npm test --workspace @shieldaai/agent-map-viewer
```

`npm run build` compiles the packages and then bundles the viewer. The viewer imports the
compiled map service (`@shieldaai/agent-map/service`, and through it
`@shieldaai/agent-guard/internal`) for its demo, so on a fresh checkout the viewer's own
build and tests fail until the packages have been compiled once. After that,
`npm run build --workspace @shieldaai/agent-map-viewer` rebuilds the viewer alone.

The build writes `dist/index.html`, `dist/app.js`, `dist/demo.js` and `dist/app.css`. Serve them with the
map service's `viewerDirectory` option (see the package README). Any static file server is
enough for the demo.

**Open synthetic demo** on the first screen needs no service at all. It runs the real
`MapService` in the page over a small in-memory fixture (three agents, one per flag
status), so every answer has the service's own shape, wording and limits. The demo is a file of its own (`demo.js`), fetched when you first open it; after that it makes no
network requests, keeps a "Demo workspace" banner visible and is not evidence of a real
executor or cloud account.

## What you see

After connecting, a **What am I looking at?** panel explains the map in four sentences;
it is closed until you open it. There are six views:

| View | What it answers |
| --- | --- |
| Agent inventory | Which agents exist, who owns them, and what one agent can reach |
| Owners | Which people, teams and services hosts name as owners, with their agents and resources |
| Resources | Which host-bound resources exist, and who may reach one (**Potential access** finds agents for a reference and action) |
| Changes | What was added, removed or changed between the two retained snapshots of a source |
| Discovery | Leads to agents nobody declared: undeclared activity and unclaimed IAM identities (all-teams readers only) |
| Health | When each part of the inventory was captured, and whether it is stale |

### Agent inventory

The sidebar lists agents, 20 per page, with a search box. Filters (owner, environment,
ownership status, lifecycle, flag) sit behind a **Filters** disclosure that shows how many
are set, so the list stays in view. Owner ID and environment are typed: any exact value is
accepted, and the values of the agents loaded so far are offered as suggestions; the Owners
view lists every owner. The sidebar
stays in place while the detail scrolls. An empty inventory says how agents get onto the
map (a host manifest declares them) rather than "no match".

Each agent carries a badge when it is flagged: **Dangerous three: Exposed**, **Mitigated**
or **Unknown**. The legend above the list says what that means: one live task can read
private data, read outside content and send data out. No badge means at least one of the
three is known not to apply.

Selecting an agent moves focus to its name. Its **Overview** leads with the two security
sections, then the facts:

1. **Boundary flags**: one row per part of the dangerous three, with its state and the
   task, tool and resource binding behind it.
2. **Outside the guard**: paths the host declared around the guard, and buckets a tool's
   cloud identity reaches beyond its grants.
3. Agent overview, deployments and tasks.
4. An optional relationship graph of the same evidence. Every identifier and relationship
   is also in a table, and "Show in graph" selects the matching node.

**Permissions** lists declared grants, tools and IAM policy candidates, and explains one
task, tool and resource selector (the form offers the agent's own tasks, tools and
selectors, and accepts any other value). **Connections & resources** lists resources, MCP
connections, bindings, identities, credential references and relationships. **Agent
changes** compares snapshots for this agent.

### Reading the evidence

- Codes are shown in words. Every status, reason, kind and yes/no value goes through one
  label table (`src/labels.mjs`); a code the viewer does not know yet still reads as words.
- A long identifier (an `opaque:` reference, a source id, an ARN) is shortened to its
  first ten and last six characters. Open it to see the full value, or use **Copy**. A
  display name leads where one exists.
- An error appears beside the control that caused it, with a retry where one makes sense.
  A page-level message stays in view while you scroll.
- Nothing here means access is allowed or safe. Declared grants and policy candidates are
  evidence; unknown stays unknown and is never shown as "none".

## Signing in

The viewer asks its own origin (`GET /auth/session`) which sign-in the service offers. A
missing or malformed answer shows a retry; it never falls back to another mode.

- **Reference credential** (loopback service). An `agm_v1.…` credential is kept in memory
  for the page only: never in browser storage, never in a URL, never sent to another
  origin. A 401 or 403 clears it and the displayed inventory.
- **Company account** (HTTPS service with OIDC). The browser holds an HttpOnly session
  cookie and a CSRF value; provider tokens never reach the page. Hiding the tab keeps your
  place: the evidence is covered (not drawn, not read out, not operable) from the moment
  the page is hidden, and when you return the session is checked once. If it is the same
  session, the view, filters, selected agent, scroll position and keyboard focus are still
  there. If the session ended meanwhile, the evidence is cleared and the sign-in page says
  why. If it is a different session (a new sign-in, possibly by someone else), everything
  read under the old one is cleared and the map opens afresh with a notice. A notice appears one minute before the session expires. Sign-out
  clears the evidence at once and ends the map session; the identity provider's own
  session follows company policy.

At most two reads run at a time. Leaving a view cancels reads that have not started;
results of a closed session never reach a new one. Queries are not retried automatically.

## Source layout

| Path | Contents |
| --- | --- |
| `src/app.jsx` | `App`: the page markup, and covering the workspace while a session is checked |
| `src/hooks/` | `use-workspace.mjs` (navigation state and what a reader may still see), `use-session.mjs` (sign-in, sign-out, session checks), `use-inventory.mjs` (agent list, health, selected agent), `use-source-choice.mjs` (default source of a view) |
| `src/views/` | One file per view: sign-in, shell, agent sidebar, agent detail, graph, explanation, owners, resources, changes, health |
| `src/components/` | Shared parts: tables and paging, the identifier with its copy button, notices |
| `src/labels.mjs` | The one table that turns service codes into words |
| `src/*-model.mjs`, `src/view-model.mjs` | Pure presentation logic and the HTTP client, testable without a browser |
| `src/demo.mjs`, `src/demo-store.mjs` | The demo: the real service over an in-memory fixture, built as `demo.js` and loaded on demand |
| `src/shims/` | Browser stand-ins for the three Node modules the service's JSON helpers import |

## Limits

- Text is rendered as inert labels; no imported HTML is interpreted.
- Responses are bounded to 4 MiB and queries to 12 seconds in the browser; the service
  applies its own tighter limits.
- The graph draws up to eight extra buckets per tool (300 edges in all) and one
  "+N more" node; the table lists them all. A graph the service leaves out as too large
  does not hide the tables.
- The server's Content Security Policy must allow scripts from `self` and styles from
  `self` with inline style attributes (Cytoscape sizes its canvas that way). No external
  fonts, images, scripts or styles are fetched.
- Layout adapts down to 375px; nothing functional is smaller than 12px; reduced motion is
  respected.

## Check it in real browsers

From the repository root on a POSIX host. Browser tooling stays in a temporary directory.

```sh
npm run build
browser_tools=$(mktemp -d)
npm install --prefix "$browser_tools" --ignore-scripts --no-audit --no-fund playwright@1.63.0 axe-core@4.14.0
"$browser_tools/node_modules/.bin/playwright" install chromium firefox webkit
node apps/agent-map/check-browser.mjs "$browser_tools" artifacts/map/chromium chromium
node apps/agent-map/check-browser.mjs "$browser_tools" artifacts/map/firefox firefox
node apps/agent-map/check-browser.mjs "$browser_tools" artifacts/map/webkit webkit
```

The check drives the demo from the keyboard (help panel, first agent readable without
scrolling at 800×600, graph, explanation, potential access, changes, discovery, health, and
all six views at 375px). It then connects to a real loopback service over a synthetic
inventory (paging, focus on the selected agent, the Filters disclosure and a typed
environment filter, a 511-task agent whose graph is too large, a failed listing and its
retry, a rejected credential) and to a local company service with a signed OIDC fixture
(a hidden tab: evidence covered at once, then scroll position, focus and place kept after
the session check; revoked sessions; sign-out). It fails on any failed assertion, uncaught page error or axe WCAG 2/2.1 A/AA
violation. The inventory is synthetic throughout; people who use assistive technology
should still try the deployed viewer.
