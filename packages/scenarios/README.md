# @shieldaai/agent-guard-scenarios

This package is a conformance suite for Agent Guard: thirteen scenarios, each with a hostile case that must be refused and a matching harmless case that must succeed, judged by handler calls and recorded effects rather than by returned decisions. It catches an integration that lets through unauthorized tools or resources, wider delegation, cross-tenant access, unapproved or reused approvals, changed tool definitions, leaked secrets, exceeded budgets, or sends after sensitive or outside content was read.

```sh
npm install @shieldaai/agent-guard @shieldaai/agent-guard-scenarios
```

Node.js 22 or later, ESM. The fixtures are synthetic: no credentials, model calls, network or destructive operations.

## Quick example

```ts
import { runConformance, scenarioCatalog } from '@shieldaai/agent-guard-scenarios';

const report = await runConformance();
console.log(`${report.passedCases} of ${report.caseCount} cases passed (catalog ${report.catalogVersion})`);
for (const result of report.results) {
  if (!result.passed) console.log(result.scenarioId, result.variant, result.failure);
}
console.log(scenarioCatalog.map(scenario => `${scenario.id} ${scenario.title}`).join('\n'));
```

Without options the suite runs against the guard, `@shieldaai/agent-guard`.

## The scenarios

| ID | What it checks |
| --- | --- |
| S01 | Unknown tools and resources outside the grants are refused |
| S02 | A child task cannot hold more than its parent |
| S03 | Administration stays with the host, not with model-callable tools |
| S04 | No external send after sensitive data was read |
| S05 | An approval covers one exact action, expires and works once |
| S06 | A changed tool definition needs a new review |
| S07 | Configured secrets cannot appear in outbound arguments |
| S08 | Revocation, policy and approval are checked again before dispatch |
| S09 | The tenant comes from the trusted task, not from arguments |
| S10 | Call, concurrency and cost budgets hold, for every ancestor |
| S11 | Arguments are parsed and normalized before the resource is resolved |
| S12 | An approval is bound to a resource version, compared again at write time |
| S13 | Sends are limited after the task read outside content |

`scenarioCatalog` holds the same list with each scenario's boundary, hostile cases, harmless case and limitations. The [scenario specification](https://github.com/ShieldaAI/agent-guard/blob/main/docs/scenarios.md) explains every one, and the [risk mapping](https://github.com/ShieldaAI/agent-guard/blob/main/docs/risks.md) relates them to the OWASP list of risks for agentic applications.

## Run selected scenarios

```js
const report = await runConformance({ scenarioIds: ['S05', 'S08'] });
```

Each selected scenario runs both of its cases. An empty list, a repeated ID or an unknown ID throws a `TypeError`, so a selection cannot pass by running nothing.

## Test your own implementation

Pass `createGuard` to run the suite against an adapter or a wrapper around the guard.

```js
import { AgentGuard } from '@shieldaai/agent-guard';

const report = await runConformance({
  createGuard: options => new AgentGuard({ ...options, onDecision: event => console.log(event.code) }),
});
```

The factory is called once for each fixture and must return a new object with the methods of the exported `GuardLike` type: `registerTool`, `approveTool`, `createTask`, `delegateTask`, `revokeTask`, `setPolicy`, `prepare`, `approve`, `execute` and `snapshot`. It must use the `clock` and `secretValues` it is given. Refusals must be `GuardError`s with the documented codes; they are recognized with `isGuardError()`, so an implementation built on a second installed copy of the guard also passes.

## The report

`runConformance()` resolves to a frozen report:

- `passed`, `scenarioCount`, `caseCount`, `passedCases` and `failedCases`;
- `catalogVersion`, the version of the checks that ran;
- `results`, one entry for each case with `scenarioId`, `variant` (`malicious` or `benign`), `passed`, the number of `assertions`, the number of `handlerInvocations`, the `denialCodes` observed and, on failure, a `failure` label.

A failure label is a fixed description of the check that failed. It never contains argument values or raw error text.

## Catalog version

The catalog has its own version, `SCENARIO_CATALOG_VERSION`, separate from the package version. Version `1.3.0` has thirteen scenarios and twenty-six cases. Compare reports by `catalogVersion`: a pass on an older catalog says nothing about checks added later.

## Timeouts

Each case has five seconds; change this with `caseTimeoutMs` (a whole number of milliseconds, at most 2,147,483,647). A case that times out is reported as failed and the run continues. The timer cannot interrupt blocking JavaScript or cancel work your adapter has started, so run the suite in a separate process if you need a hard limit.

## What a pass does not mean

- It is not a security certification. A pass covers these fixtures, in one process.
- It does not show that a production agent cannot reach a backend without going through your integration.
- It does not test prompt-injection detection, Model Context Protocol (MCP) transports or a deployment.
- It does not lock or refresh real resources: in S12 the fixture handler compares versions itself, and a real service must do that atomically with its write.
- It does not interpret `inputSchema`: S11 checks the tool's own `parse` function.

Apache-2.0. Copyright 2026 ShieldaAI contributors.
