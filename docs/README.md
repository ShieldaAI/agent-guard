# Documentation

Start with the [project README](../README.md) for what Agent Guard is and a five-minute
example. The [glossary](glossary.md) defines the terms.

## Use it

| Page | What it is for |
| --- | --- |
| [Tool-permissions walkthrough](guides/tool-permissions.md) | The first example, step by step: a denial, an approval, a refused replay. |
| [Package guide](package-guide.md) | Which package to install for what. |
| [Delegation](guides/delegation.md) | Hand part of a task to a sub-agent. |
| [Audit log](guides/audit-log.md) | Record every decision. |
| [OpenAI and Anthropic ticket workflow](guides/provider-ticket-workflow.md) | The guard inside a real tool-calling loop. |
| [Verified MCP credentials](guides/verified-mcp-credentials.md) | Connect to a remote MCP server with a checked access token. |
| [Decision traces](guides/decision-traces.md) | Export what the executor decided, without payloads. |
| [Ledger rollback](guides/ledger-rollback.md) | Detect a restored old copy of the executor's ledger. |
| [Company history](guides/company-history.md) | Keep finished requests in files you own. |
| [Agent cartography](guides/agent-cartography.md) | Build an inventory of your agents (experimental). |

## Understand it

| Page | What it is for |
| --- | --- |
| [Risks and how Agent Guard handles them](risks.md) | The OWASP agentic top 10, risk by risk. |
| [Standards and further reading](standards.md) | The same controls against other frameworks, and articles that explain the problem. |
| [Support and limits](support-and-limits.md) | What it enforces, what stays with you, limits per package. |
| [Threat model](threat-model.md) | Who is trusted, what is assumed hostile. |
| [Architecture](architecture.md) | How a call flows and where state lives. |

## Reference

| Page | What it is for |
| --- | --- |
| [API contract](api-contract.md) | Signatures and exact rules. |
| [Error codes](errors.md) | Every code, whether a retry is safe, the usual cause. |
| [Scenarios](scenarios.md) | The thirteen hostile and ordinary test cases. |
| [Inventory formats](agent-cartography-contract.md) | Host manifest and snapshot fields. |
| [Release notes](releases/1.1.0.md) and [changelog](../CHANGELOG.md) | What changed. |

## Evaluate a deployment

These are for teams checking their own installation, not for everyday use.

| Page | What it is for |
| --- | --- |
| [Provider outcome evaluation](guides/provider-outcome-evaluation.md) | Compare guarded and unguarded hosts on paired tasks. |
| [Model-selected provider trials](guides/model-selected-provider-trials.md) | Measure what a live model does with your cases. |
| [MCP isolation procedure](guides/mcp-isolation-acceptance.md) | Run an MCP server in an isolated container and check the boundary. |
| [Build artifact admission](guides/build-artifact-admission.md) | Admit signed build outputs into the sandbox flow. |
| [Pilot review](guides/pilot-review.md) | Verify a pilot's evidence bundle. |
| [Operator usability check](guides/operator-usability-check.md) | Test the review screen with real operators. |

## Operate it

| Page | What it is for |
| --- | --- |
| [Docker isolation profile](../deployment/README.md) | The sandbox profile and how to verify it. |
| [Agent Ops runbook](../deployment/production/README.md) | Run the reference review app. |
| [Cartography runbook](../deployment/cartography/RUNBOOK.md) | Run the collector, graph and Agent Map. |
| [Releasing](releasing.md) | How maintainers publish. |
