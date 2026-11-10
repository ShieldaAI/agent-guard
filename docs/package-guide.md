# Choose a package for agent tools and model calls

Use these existing libraries to authorize AI agent tool calls, validate LLM
responses, or monitor security advisories for your dependencies. Each works
without a Shielda account. Start with the package that solves your current task.

## Find the right package

| Your task | Package and documentation | Runtime and boundary |
| --- | --- | --- |
| Restrict which tools an AI agent can call and on which resources | [Agent Guard](../packages/core/README.md), `@shieldaai/agent-guard` | Node.js 22+; registered calls in one process, with in-memory state |
| Approve MCP tool metadata and scope tool calls to a task | [MCP adapter](../packages/mcp/README.md), `@shieldaai/agent-guard-mcp` | Node.js 22+; the host supplies trusted identity, resource resolution and transport policy |
| Persist approvals and budget admission across restarts | [Durable executor](../packages/executor/README.md), `@shieldaai/agent-guard-executor` | Node.js 22.13+; one authority owner, rather than distributed enforcement |
| Run paired malicious and benign tool-authorization fixtures | [Conformance scenarios](../packages/scenarios/README.md), `@shieldaai/agent-guard-scenarios` | Node.js 22+; synthetic fixtures, not a production security certification |
| Query AI agent and MCP inventory, changes and access explanations | [Agent Map](../packages/agent-map/README.md), `@shieldaai/agent-map` | Node.js 22.13+; a read-only service requiring configured inventory and Neo4j |
| Validate JSON model responses with Zod and handle retries in TypeScript | [SafeCall Node](https://github.com/GuardianMesh/llm-safecall-node#readme), `llm-safecall` on npm | Node.js 22+ and Zod 4; model-call validation, not tool authorization |
| Validate model responses with Pydantic and handle retries in Python | [SafeCall Python](https://github.com/GuardianMesh/llm-safecall#readme), `llm-safecall` on PyPI | Python 3.10+; independent Python package with its own version |
| Monitor dependency advisories against an inventory with local evidence and alerts | [Security Watch](https://github.com/ShieldaAI/security-watch#readme), `@shieldaai/security-watch` | Node.js 24.10+; experimental advisory monitoring, with human review of applicability |

The published Agent Guard packages remain experimental `0.1.0-alpha.3`; this
checkout prepares an unpublished `0.1.0` candidate with open release gates.
Security Watch has its separate experimental release policy. Read
their boundaries before deploying them. Agent Guard controls calls routed through
it; it is not an OS sandbox. SafeCall's known-pattern filters do not establish
that text is safe to follow.

## Start with tool authorization

Install the core when you need scoped resources, tenant checks, exact-action
approvals or task budgets:

```sh
npm install @shieldaai/agent-guard@alpha
```

The [tool-permissions walkthrough](guides/tool-permissions.md) registers a local
tool, rejects an ungranted resource and missing approval, then runs one approved
action and rejects replay. It needs no API key or external service. The trusted
application creates task identities, resolves
ownership and authenticates reviewers for actions requiring approval.

For MCP tools, add `@shieldaai/agent-guard-mcp@alpha`. For persistent authority
state, add `@shieldaai/agent-guard-executor@alpha`. Install matching Guard package
versions. The install commands above select the published alpha. This checkout
targets unpublished `0.1.0`; build and install its local tarballs together for
candidate features. See the [candidate notes](releases/0.1.0.md) for open gates
and the [alpha.3 notes](releases/0.1.0-alpha.3.md) for publication verification.

To evaluate the existing synthetic fixtures without a model provider:

```sh
npm install @shieldaai/agent-guard-scenarios@alpha
node --input-type=module -e "import { runConformance } from '@shieldaai/agent-guard-scenarios'; const r = await runConformance(); console.log(r.passed, r.passedCases, r.caseCount); if (!r.passed) process.exitCode = 1;"
```

The published alpha.3 catalog (1.2.0) runs twelve paired scenarios and prints `true 24 24`
when all cases pass; this checkout's catalog (1.3.0) runs thirteen and prints `true 26 26`. The [scenario reference](scenarios.md) explains what they cover.

## Start with model response validation

For Zod validation and retry handling on Node.js:

```sh
npm install llm-safecall zod@^4.6.7
LLM_PROVIDER=mock npx llm-safecall --prompt 'Hello'
```

The mock command checks the installed CLI without provider credentials. Follow
the [Node response-validation example](https://github.com/GuardianMesh/llm-safecall-node#validate-a-response)
for typed JSON, or try the [local Zod walkthrough](https://github.com/GuardianMesh/llm-safecall-node/blob/main/docs/validated-responses.md)
without credentials. SafeCall 0.4.0 raises errors by default; the optional display
fallback is a string, not validated schema output.

For the separate Python distribution, use an isolated environment:

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install llm-safecall
LLM_PROVIDER=mock llm-safecall --prompt 'Hello'
```

See the [Python response-validation example](https://github.com/GuardianMesh/llm-safecall#validate-a-response)
for Pydantic output and optional provider extras. Python and Node releases have
different version numbers; do not transfer API names between them.

The [local Pydantic walkthrough](https://github.com/GuardianMesh/llm-safecall/blob/main/docs/validated-responses.md)
demonstrates validation and retries without a live provider.

## Start with dependency advisory monitoring

Read the [Security Watch setup and dry-run instructions](https://github.com/ShieldaAI/security-watch#install-and-preview).
The [offline advisory preview](https://github.com/ShieldaAI/security-watch/blob/main/docs/offline-advisory-preview.md)
uses the published package's fictional inventory and advisory fixture.
Begin with a fictional inventory, AI analysis disabled and notification routes
disabled. Configure your actual inventory and review findings before activating
Slack or email delivery. Advisories and coverage receipts are evidence for review;
an empty result does not prove that dependencies are safe.

## Query inventory after it is configured

Agent Map supplies scoped HTTP and MCP reference queries over published
Cartography inventory. It does not authorize or execute agent actions. The
[package guide](../packages/agent-map/README.md) covers its required host-owned
configuration; the viewer and Python collector are separate source components.
Alpha.3 fixes the installed command launchers. For the older alpha.2 package on
macOS, invoke the launcher directly with
`node node_modules/@shieldaai/agent-map/dist/cli.js --help` if its npm command
shortcut produces no output. See the [release notes](releases/0.1.0-alpha.2.md)
for the release boundary.

## Select rows across server pages

[select-all-matching](https://github.com/ShieldaAI/select-all-matching#readme) is a
separate framework-independent table-selection library. It represents every row
matching a server-defined scope except selected exclusions, without loading all
IDs. Install its release candidate with `npm install select-all-matching@next`.
It supplies no table UI or authorization; the server must recheck access when a
bulk operation runs.
