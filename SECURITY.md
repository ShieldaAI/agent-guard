# Security policy

This project is an experimental alpha. No version is certified for unattended production privilege enforcement. The current alpha receives fixes; there is no long-term support promise.

Please report vulnerabilities with GitHub's **Report a vulnerability** flow at https://github.com/ShieldaAI/agent-guard/security/advisories/new. Include the affected version, a synthetic reproduction, expected behavior and observed effects. Avoid real credentials or customer data. Do not post an exploitable issue publicly while private reporting is available.

The supported boundary is registered tool execution through a trusted host in a single process. The model must not control administration APIs or obtain a bypass route to credentials and tools. The detailed assumptions and limitations are in [the threat model](docs/threat-model.md).

Passing tests is evidence for those fixtures, not proof of universal injection resistance. Hard isolation, persistent authorization state and distributed consistency are outside the first alpha.
