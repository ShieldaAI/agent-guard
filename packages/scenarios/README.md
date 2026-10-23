# @shieldaai/agent-guard-scenarios

Versioned protection scenarios and executable synthetic fixtures for the Agent Guard public API. Node.js 22+, ESM. Experimental alpha.

```ts
import { runConformance, scenarioCatalog } from '@shieldaai/agent-guard-scenarios';

const report = await runConformance();
console.log(report.passed, report.passedCases, report.caseCount);
console.table(report.results);
console.log(scenarioCatalog);
```

Run selected scenarios with `runConformance({ scenarioIds: ['S05', 'S08'] })`. The default suite executes malicious and benign variants of all ten scenarios. It checks handler invocations and synthetic effects, not merely decision objects. Fixtures do not use real credentials, models, network services or destructive operations.

The scenarios cover unauthorized tools/resources, delegation, protected administration, sensitive export, action-bound approval, metadata drift, outbound secrets/canaries, revocation/control failures, tenants and budgets. The [scenario specification](https://github.com/ShieldaAI/agent-guard/blob/main/docs/scenarios.md) explains each boundary.

To exercise a compatible implementation, supply `createGuard(options)` in the options object. The factory must honor the provided clock and secret configuration and return the structural `GuardLike` API. Denials use the exported `GuardError` and its documented reason codes. Each fixture receives an isolated instance; no shared factory state is required.

A passing report applies to these fixtures in one process. It is not a security certification, injection-detector benchmark, MCP transport test or proof that a production agent cannot bypass its integration. Errors after actual handler invocation are tested separately from denials that must prevent invocation.

Apache-2.0. Copyright 2026 ShieldaAI contributors.
