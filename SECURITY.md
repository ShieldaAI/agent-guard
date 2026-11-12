# Security policy

Security fixes are released for the latest 1.x version. The `0.1.0-alpha` prereleases
are no longer supported; upgrade to 1.0.0 or later. A release is not a production
certification: the supported boundary is described below and in
[support and limits](docs/support-and-limits.md). Run it on a Node.js release line that
still receives security updates.

Please report vulnerabilities through [GitHub private vulnerability reporting](https://github.com/ShieldaAI/agent-guard/security/advisories/new). Include the affected version, a synthetic reproduction, expected behavior and observed effects. Avoid real credentials or customer data. Do not post an exploitable issue publicly while private reporting is available.

The supported boundary is registered tool execution through a trusted host in a single process. The model must not control administration APIs or obtain a bypass route to credentials and tools. The detailed assumptions and limitations are in [the threat model](docs/threat-model.md).

Passing tests is evidence for those fixtures, not proof of universal injection resistance. The embedded core keeps state in memory. The optional executor adds a single-owner encrypted SQLite ledger and a separate Docker profile for isolated workloads. It does not provide distributed quotas or a sandbox for ordinary in-process handlers. See [support and limits](docs/support-and-limits.md) before choosing a deployment boundary.

## Automated checks

The workflows configure a Node.js test matrix, CodeQL analysis for TypeScript and GitHub Actions, and dependency review for pull requests. Dependency review rejects newly introduced advisories rated moderate or higher. CodeQL also runs weekly, and Dependabot proposes npm and GitHub Actions updates weekly. Review dependency changes before merging; these tools do not replace code review or the threat model.

Workflow actions are pinned to commit hashes. CI uses read-only repository access and does not retain checkout credentials. Only the CodeQL analysis job can upload security findings. No workflow has npm publishing credentials.
