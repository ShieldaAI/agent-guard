# P0 reference deployment verification — 2026-11-05

The implementation targets the selected durable reference ticket service, standard
OIDC and a single-owner Linux Docker Compose deployment. The application and
deployment contracts are in [Agent Ops](../apps/agent-ops/README.md) and the
[Linux runbook](../deployment/production/README.md). This record covers the source
implementation and disposable local deployment checks, not a customer installation.

## Requirements and implementation

| P0 requirement | Implemented boundary |
| --- | --- |
| Single-owner Linux deployment | Exclusive SQLite owners, nonroot UID 10001, read-only runtime/config mounts, dropped capabilities, bounded resources/logs, loopback publication, strict HTTPS origin and no Docker socket. |
| Real ticket workflow | Persisted ticket records, exact resource versions, one-call task budgets, stored action/operation identity, and an atomic conditional update plus receipt. Enrolled agents can propose and read only their own scoped requests. |
| Authenticated approvals | Verified OIDC code exchange with signed tokens, state/nonce/PKCE and explicit subject-to-tenant/role enrollment. Secure sessions, CSRF checks, per-reviewer attribution and a final authorization check before effects. |
| Safe archival | Whole-family preview and retirement, active/unknown/reference blockers, transactional encrypted archives, permanent bounded identifier tombstones, and cross-store archival recovery. |
| Key rotation | Offline multi-key staging before re-encryption, atomic ledger/witness commit, retryable partial two-store rotation, preserved authority and per-archive random keys. Observation consumers must reenroll after outer-key rotation. |
| Recovery | Conservative startup invalidation, durable unknown reservations, receipt-only reconciliation, exact business-marker recovery, cold restore checks and stale-backup rejection. Missing evidence never authorizes a retry. |
| Clear operator UX | Exact change/version/digest/expiry, distinct review/outcome states, visible reviewer and receipt, explicit recovery, short-lived archival review, host-only key guidance and sign-in recovery. |

## Verification evidence

- Final `npm test`: **968 passed, 0 failed, 0 skipped** on Node 26.12.0/macOS,
  with the pinned Docker sandbox and MCP-isolation fixtures enabled.
- `npm run check` also passed the package/tarball consumer checks. The final
  application suite contains **18** real workflow and HTTPS/OIDC tests.
- Browser checks: **13** synthetic contract states and **8** states against the
  real local HTTPS/OIDC/encrypted-SQLite service, using Chromium 153.0.8010.12 and
  axe 4.14.0. Zero automated accessibility violations or page errors. Keyboard and
  375-pixel layouts were checked; desktop/mobile screenshots were visually reviewed.
- The real browser workflow confirmed two approvals produced two writes, denial
  produced no write, receipt reconciliation produced no additional write, and
  archival preserved the business receipt. A committed write followed by a lost
  browser response requires refresh rather than a repeated approval.
- Hardened Linux verification passed on Linux/arm64, Node 24.22.1 and Docker
  29.5.2. The measured verification image was
  `sha256:905c887cc5cd1c3cccb3f05d0e6d9a9bc7a38b954c847bf4c87da57ecde27857`.
  All eleven checked runtime, UI and executor module files matched the workspace
  bytes inside this image. The [dated Linux evidence](validation/production-linux-2026-11-05.json)
  records exact image/script hashes and confirms the production and verification
  stages contain identical runtime code/dependencies; test fixtures are excluded
  from the production stage.
- Linux scenarios covered signed OIDC, CLI initialization/start, reviewed update,
  SIGKILL/restart, session and pending-review invalidation, second-owner rejection,
  current cold restore without witness rollback, partial and complete two-store
  rotation, subsequent update, HTTPS archival and stale-restore refusal. A
  separate fault scenario recovered a committed backend receipt without repeating
  the effect.
- The new `production-profile (linux, node24)` CI job runs the hardened Linux
  scenarios on amd64 and retains bounded evidence. Existing platform checks remain
  configured. This local review does not claim a hosted CI run for the new branch.

The regression suite also covers failures between retirement and archive commit,
between archive commit and the business marker, and after successful execution
but before success reporting. A receipt whose terminal executor action has been
pruned can finish its business marker only with exact receipt matching and settled
one-call accounting; unresolved reservations cannot use that path.

Run `npm run check`, the two browser scripts under `apps/agent-ops`, and
`deployment/production/check-linux.mjs` using the runbook's verification image to
repeat these checks. Local logs, browser reports and selected screenshots are
retained under the ignored `artifacts/production-p0/` directory.

## Installation boundaries and next work

The real installation still needs its company OIDC/TLS enrollment, protected
configuration, independent witness/backup custody, monitoring and storage validation.
SIGKILL and cold file restoration are not physical host power-loss tests.

The reference backend retains at most 500 tickets and 4,000 lifetime
requests/receipts. Task archival does not delete those business records. The
keyring holds four retained keys. Both fail closed at their limits; reviewed
retention/migration and key retirement belong in the next operational increment.
Missing or mismatched receipts remain unconfirmed and block archival.

The [production plan](production-plan.md) extends the existing Agent Map and
Cartography work with agent owners, identities, tools, permissions, resources,
credential references, provenance, freshness and drift. These graph extensions
remain planned work, with declared, evaluated and observed permission evidence
kept distinct from execution authority.
