# Security policy

The latest published version is the experimental `0.1.0-alpha.3`. This checkout
holds **0.1.0, approved and not yet published**; the Node HIGH security review is a
post-release follow-up recorded in the
[release notes](docs/releases/0.1.0.md). It is not a production certification.
Security fixes target the current maintained release/candidate; older versions
have no long-term support commitment. A version without an alpha suffix does
not extend the documented deployment boundary or promise 1.x API stability.

Please report vulnerabilities through [GitHub private vulnerability reporting](https://github.com/ShieldaAI/agent-guard/security/advisories/new). Include the affected version, a synthetic reproduction, expected behavior and observed effects. Avoid real credentials or customer data. Do not post an exploitable issue publicly while private reporting is available.

The supported boundary is registered tool execution through a trusted host in a single process. The model must not control administration APIs or obtain a bypass route to credentials and tools. The detailed assumptions and limitations are in [the threat model](docs/threat-model.md).

Passing tests is evidence for those fixtures, not proof of universal injection resistance. The embedded core keeps state in memory. The optional executor adds a single-owner encrypted SQLite ledger and a separate Docker profile for isolated workloads. It does not provide distributed quotas or a sandbox for ordinary in-process handlers. See the [requirements and design](docs/support-and-limits.md) and [current verification and open gates](docs/support-and-limits.md) before choosing a deployment boundary.

## Automated checks

The workflows configure a Node.js test matrix, CodeQL analysis for TypeScript and GitHub Actions, and dependency review for pull requests. Dependency review rejects newly introduced advisories rated moderate or higher. CodeQL also runs weekly, and Dependabot proposes npm and GitHub Actions updates weekly. Review dependency changes before merging; these tools do not replace code review or the threat model.

Workflow actions are pinned to commit hashes. CI uses read-only repository access and does not retain checkout credentials. Only the CodeQL analysis job can upload security findings. No workflow has npm publishing credentials.

The release review records the status of hosted checks. Configuration alone does not establish that a scan has run successfully.
