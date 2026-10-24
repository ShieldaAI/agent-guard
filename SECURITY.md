# Security policy

This project is an experimental alpha and has not been certified for enforcing production permissions without human oversight. Security fixes target the current alpha; older versions have no long-term support commitment.

Please report vulnerabilities through [GitHub private vulnerability reporting](https://github.com/ShieldaAI/agent-guard/security/advisories/new). Include the affected version, a synthetic reproduction, expected behavior and observed effects. Avoid real credentials or customer data. Do not post an exploitable issue publicly while private reporting is available.

The supported boundary is registered tool execution through a trusted host in a single process. The model must not control administration APIs or obtain a bypass route to credentials and tools. The detailed assumptions and limitations are in [the threat model](docs/threat-model.md).

Passing tests is evidence for those fixtures, not proof of universal injection resistance. This alpha does not provide process isolation, persistent authorization state or shared state across workers.

## Automated checks

The workflows configure a Node.js test matrix, CodeQL analysis for TypeScript and GitHub Actions, and dependency review for pull requests. Dependency review rejects newly introduced advisories rated moderate or higher. CodeQL also runs weekly, and Dependabot proposes npm and GitHub Actions updates weekly. Review dependency changes before merging; these tools do not replace code review or the threat model.

Workflow actions are pinned to commit hashes. CI uses read-only repository access and does not retain checkout credentials. Only the CodeQL analysis job can upload security findings. No workflow has npm publishing credentials.

The release review records the status of hosted checks. Configuration alone does not establish that a scan has run successfully.
