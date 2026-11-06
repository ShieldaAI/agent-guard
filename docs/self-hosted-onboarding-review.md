# Self-hosted onboarding and configurable limits — 2026-11-05

Each company owns its installation, identity enrollment, ticket data, keys and
backup custody. The implementation adds private local onboarding and reviewed
configuration/data changes to the existing single-owner Linux profile. Follow
the [company onboarding runbook](../deployment/production/README.md#company-onboarding)
and its [manifest example](../deployment/production/onboarding.example.json).

## Configurable policy

| Setting | Existing default | Validated range |
| --- | ---: | ---: |
| Company tickets | 500 | 1–10,000 |
| Retained requests and receipts | 4,000 | 1–20,000 |
| Live backend state | 16 MiB | 1–64 MiB |
| Live executor state | 16 MiB | 1–64 MiB |
| Retained encryption keys | 4 | 1–64 |

These are installation-wide engineering bounds. Byte limits apply to decoded
live state, separately from encrypted archive storage. Resource sizing still
depends on the host and workload. Increasing retention does not increase any
agent's grants, call count, cost budget or deadline.

Configuration changes use an offline preview and exact review digest. Startup
refuses a configuration/persisted-policy mismatch. Lowering a limit below retained
usage is rejected without deleting data or keys. Both stores remain exclusively
owned throughout the change. If interrupted between the key-policy and backend
policy commits, preview/apply can finish the change while startup stays closed.
Old default-policy installations retain their existing defaults.

## Company onboarding and imports

`onboard` validates a private company manifest and creates a new private bundle
atomically. It copies company-provided TLS/OIDC files, creates the keyring, records
the initial owner subject and produces the ticket seed/configuration. It rejects
an existing output bundle and does not create durable authority. No hosted account,
public bootstrap endpoint or demo company data is added.

`preflight` checks TLS key/certificate/hostname, private and separate custody paths,
explicit identity bindings, key policy, OIDC discovery and existing state. Discovery
does not prove client credentials or account binding; the first signed browser
login verifies those. An empty seed is supported, so data can be enrolled later.

`import-tickets` previews company data and requires the exact digest to apply.
Only new ticket IDs belonging to enrolled tenants can be added. Existing versions,
requests, receipts and approval history cannot be overwritten. Bulk input remains
bounded to 8 MiB and 100,000 JSON nodes, with strict duplicate-member and numeric
validation. Ordinary evidence parsers retain their smaller default node budget.

The operator-only Setup view displays company scope, OIDC issuer/callback, running
configuration health, current capacities and host commands. It does not reveal
secret values or the installation's private file paths. Generated Compose commands
honor `AGENT_OPS_CONFIG_FILE`. The UI supports empty installations, capacity errors,
tenant-scoped Previous/Next paging and mobile/keyboard navigation.

## Verification

- Full `npm run check`: **997 tests passed, 0 failed, 0 skipped**, followed by
  successful installed package and command checks. Host: Node 26.12.0/macOS;
  pinned Docker sandbox/isolation fixtures enabled.
- Application integration suite: **38 tests passed**, including actual 10,000-row
  company import, tenant paging, more than four retained rotation keys, rejected
  shrinkage, stale previews, partial policy recovery and preservation of receipts.
- Boundary checks prove an over-capacity initial seed creates no authority files
  or partial bundle, invalid custody paths are rejected, and preflight preserves
  existing state while making only local OIDC discovery GET requests.
- Final HTTP regressions: **6 tests passed**, including setup authorization,
  redaction, canonical paging parameters and company configuration path handling.
- Browser checks: **19 synthetic states and 13 real-service states**, with zero
  automated accessibility violations or page errors. The real service uses a
  local signed OIDC provider and encrypted witnessed SQLite. It verifies empty
  company setup, 505 tenant tickets across pages, approvals, denial, receipt-only
  recovery and archival. Desktop and mobile screenshots were visually reviewed.
- The existing Linux CI gate now runs company onboarding, preflight, reviewed
  capacity changes, reviewed imports and rotation beyond four keys, as well as
  the original restart/restore/recovery scenarios. The local hardened Linux run
  passed on Node 24.22.1/arm64, including a 2,000-ticket import, paging through all
  2,001 enrolled records and five retained keys under an eight-key policy. The
  [dated Linux evidence](validation/self-hosted-onboarding-2026-11-05.json) records
  exact images/script hashes. Production and verification images share 4,302
  identical runtime files; test-only fixtures remain outside the production image.
  Fourteen checked runtime/UI/compiled modules also match the workspace bytes.

Local logs and screenshots are retained in the ignored
`artifacts/self-hosted-onboarding/` directory. Repeat the checks with `npm run check`,
the two browser scripts in `apps/agent-ops`, and the Linux verifier from the runbook.

This integration imports company JSON ticket data into the durable local service.
It does not synchronize a live Jira/Linear backend. Key retirement, deletion of
historical business receipts, larger-scale storage architecture and distributed
ownership remain separate work. No retention change silently discards authority.
