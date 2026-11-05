# Restrict AI agent tool calls to approved resources in TypeScript

An agent choosing a tool does not establish permission to use it. Agent Guard
lets the trusted application register tools, grant a task access to particular
resources, and require approval of an exact prepared action.

This local example authorizes one synthetic record, rejects another, and checks
that a rejected or replayed action never runs the handler. It uses the published
`0.1.0-alpha.2` package, no model provider and no external side effects.

Watch the [64-second annotated replay](../media/tool-permissions.gif) or run the
example below. The animation uses verified output, with pauses for explanation.

## Install

Use Node.js 22 or newer in a new directory:

```sh
mkdir guard-demo
cd guard-demo
npm init -y
npm install --ignore-scripts --save-exact @shieldaai/agent-guard@0.1.0-alpha.2
```

## Run the example

Save this as `tool-permissions.mjs`:

```js
import assert from 'node:assert/strict';
import { AgentGuard, GuardError } from '@shieldaai/agent-guard';

// Synthetic records only. The trusted host supplies identity and ownership.
const guard = new AgentGuard();
let handlerCalls = 0;
const fingerprint = guard.registerTool({
  name: 'records.archive',
  description: 'Archive one synthetic record',
  requiresApproval: true,
  parse(args) {
    if (!args || typeof args !== 'object' || Array.isArray(args) ||
        Object.keys(args).length !== 1 || typeof args.recordId !== 'string') {
      throw new Error('Expected one recordId');
    }
    return { recordId: args.recordId };
  },
  resolve: args => ({ resourceId: args.recordId, tenantId: 'demo-company' }),
  execute: args => {
    handlerCalls++;
    return { value: { recordId: args.recordId, status: 'archived' } };
  },
});
guard.approveTool('records.archive', fingerprint);
const task = guard.createTask({
  id: 'archive-demo', principalId: 'demo-operator', tenantId: 'demo-company',
  grants: [{ tool: 'records.archive', resources: ['record-A'] }],
  budget: { maxCalls: 1, maxConcurrent: 1, maxCost: 0, deadline: Date.now() + 60_000 },
});

async function expectDenied(label, code, operation, expectedCalls) {
  await assert.rejects(operation, error => error instanceof GuardError && error.code === code);
  assert.equal(handlerCalls, expectedCalls);
  console.log(`DENIED ${label}: ${code}; handler calls: ${handlerCalls}`);
}

await expectDenied('ungranted resource', 'GRANT_DENIED', () =>
  guard.prepare(task, { tool: 'records.archive', args: { recordId: 'record-B' } }), 0);
const prepared = await guard.prepare(task, {
  tool: 'records.archive', args: { recordId: 'record-A' },
});
await expectDenied('without approval', 'APPROVAL_REQUIRED', () => guard.execute(prepared), 0);

// A real host authenticates the reviewer before calling approve().
const approvalId = guard.approve(prepared, {
  approverId: 'fixture-reviewer', expiresAt: Date.now() + 30_000,
});
const result = await guard.execute(prepared, { approvalId });
assert.equal(result.recordId, 'record-A');
assert.equal(result.status, 'archived');
assert.equal(handlerCalls, 1);
console.log(`ALLOWED approved record-A: ${result.status}; handler calls: ${handlerCalls}`);
await expectDenied('replay', 'ACTION_USED', () => guard.execute(prepared, { approvalId }), 1);
console.log('All assertions passed. In-process fixtures; no API key or external side effects.');
```

```sh
node tool-permissions.mjs
```

Expected output:

```text
DENIED ungranted resource: GRANT_DENIED; handler calls: 0
DENIED without approval: APPROVAL_REQUIRED; handler calls: 0
ALLOWED approved record-A: archived; handler calls: 1
DENIED replay: ACTION_USED; handler calls: 1
All assertions passed. In-process fixtures; no API key or external side effects.
```

## Apply the pattern to an application

The application owns the guard, task identity, resource ownership and approval
interface. Give the model a dispatcher for its host-selected task. In this
fixture, `demo-company` and `fixture-reviewer` are trusted demonstration values;
in an application, resolve the tenant from trusted service data and authenticate
the reviewer before calling `approve()`.

The grant selects `record-A`; the approval is bound to one immutable prepared
action. A real backend must also authorize the operation and atomically check
any approved resource version at the effect. The library cannot control a
backend call that bypasses it.

Core state is in memory and cancellation is cooperative. For persistent authority
state, read the [executor guide](../../packages/executor/README.md). For MCP tool
metadata and managed connections, read the [MCP guide](../../packages/mcp/README.md).
Both have additional deployment responsibilities.

See the [API contract](../api-contract.md), [threat model](../threat-model.md),
[package selection guide](../package-guide.md), and
[standalone example](../../examples/tool-permissions.mjs).
