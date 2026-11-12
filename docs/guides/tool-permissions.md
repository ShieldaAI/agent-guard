# Tool permissions: a first walkthrough

An agent that picks a tool has not been given permission to use it. In this
walkthrough you put one tool behind Agent Guard and watch it refuse a call,
wait for an approval, run the call once and refuse a replay.

Everything runs on your machine with made-up records. You need no API key and no
model.

## What you will achieve

A script of about sixty lines that prints:

```text
DENIED ungranted resource: GRANT_DENIED; handler calls: 0
DENIED without approval: APPROVAL_REQUIRED; handler calls: 0
ALLOWED approved record-A: archived; handler calls: 1
DENIED replay: ACTION_USED; handler calls: 1
```

The [annotated replay](../media/tool-permissions.gif) shows the same four
results.

## Prerequisites

- Node.js 22 or later (`node --version`)
- A terminal and a text editor

## 1. Install

```sh
mkdir guard-demo
cd guard-demo
npm init -y
npm install @shieldaai/agent-guard
```

Create an empty file named `tool-permissions.mjs`. Each step below adds a block
to the end of that file.

## 2. Register a tool

A tool is one operation the agent may ask for. You describe it with three
functions:

- `parse` checks the arguments and returns a clean copy.
- `resolve` says which resource the call touches and which tenant owns it.
- `execute` does the work. This is the handler.

```js
import { AgentGuard, isGuardError } from '@shieldaai/agent-guard';

const guard = new AgentGuard();
let handlerCalls = 0;

const fingerprint = guard.registerTool({
  name: 'records.archive',
  description: 'Archive one record',
  requiresApproval: true,
  // parse: accept exactly { recordId: string } and nothing else.
  parse(args) {
    if (args === null || typeof args !== 'object' || Array.isArray(args) ||
        Object.keys(args).length !== 1 || typeof args.recordId !== 'string') {
      throw new Error('Expected one recordId');
    }
    return { recordId: args.recordId };
  },
  // resolve: which resource does this call touch, and whose is it?
  resolve: args => ({ resourceId: args.recordId, tenantId: 'demo-company' }),
  // execute: do the work. Here it only counts and returns a value.
  execute(args) {
    handlerCalls++;
    return { value: { recordId: args.recordId, status: 'archived' } };
  },
});
guard.approveTool('records.archive', fingerprint);
```

`registerTool` returns a fingerprint, a hash of the tool's definition.
`approveTool` tells the guard that your code accepts that definition. If the
definition changes later, the fingerprint changes and the tool is refused until
you approve it again.

`requiresApproval: true` means a person must approve every call to this tool.

## 3. Create a task

A task is one piece of work for an agent. It says who the work is for, which
tools and resources it may use, and how much it may do.

```js
const task = guard.createTask({
  id: 'archive-demo',
  principalId: 'demo-operator',
  tenantId: 'demo-company',
  grants: [{ tool: 'records.archive', resources: ['record-A'] }],
  budget: { maxCalls: 1, maxConcurrent: 1, maxCost: 0, deadline: Date.now() + 60_000 },
});
```

This task may archive `record-A` and nothing else. It may make one call, and it
ends in sixty seconds.

`task` is a handle. Your code keeps it and decides which agent works under it.
The agent never receives the handle; it only sends a tool name and arguments.

## 4. See a denial

Every call has two steps. `prepare` checks the call and freezes it. `execute`
checks again and runs the handler.

Ask for a record the task was not granted:

```js
// Runs a call that should be refused and prints why.
async function expectDenied(label, call) {
  try {
    await call();
    console.log(`NOT DENIED ${label}`);
  } catch (error) {
    if (!isGuardError(error)) throw error;
    console.log(`DENIED ${label}: ${error.code}; handler calls: ${handlerCalls}`);
  }
}

await expectDenied('ungranted resource', () =>
  guard.prepare(task, { tool: 'records.archive', args: { recordId: 'record-B' } }));
```

Run `node tool-permissions.mjs`:

```text
DENIED ungranted resource: GRANT_DENIED; handler calls: 0
```

The guard refused at `prepare`, and the handler did not run. Every refusal is an
error with a stable `code`; `isGuardError` tells you the error came from the
guard. The [error catalog](../errors.md) explains each code.

## 5. Ask for the granted record, without approval

```js
const prepared = await guard.prepare(task, {
  tool: 'records.archive',
  args: { recordId: 'record-A' },
});
await expectDenied('without approval', () => guard.execute(prepared));
```

```text
DENIED without approval: APPROVAL_REQUIRED; handler calls: 0
```

`prepare` succeeded this time: the task holds a grant for `record-A`. The result
is a prepared action, a frozen record of exactly what would run.
`prepared.requiresApproval` is `true`, so `execute` refuses until someone
approves.

## 6. Approve and run

```js
// A real host authenticates the reviewer and shows them prepared.action first.
const approvalId = guard.approve(prepared, {
  approverId: 'demo-reviewer',
  expiresAt: Date.now() + 30_000,
});
const result = await guard.execute(prepared, { approvalId });
console.log(`ALLOWED approved record-A: ${result.status}; handler calls: ${handlerCalls}`);
```

```text
ALLOWED approved record-A: archived; handler calls: 1
```

The approval belongs to this one prepared action. It cannot be moved to
different arguments or another record, and it stops working at `expiresAt`.

## 7. Try a replay

```js
await expectDenied('replay', () => guard.execute(prepared, { approvalId }));
```

```text
DENIED replay: ACTION_USED; handler calls: 1
```

A prepared action runs at most once. The handler count stays at 1.

## What can go wrong

| You see | Cause | Fix |
| --- | --- | --- |
| `ERR_MODULE_NOT_FOUND` | The package is not installed in this directory. | Run `npm install @shieldaai/agent-guard` in `guard-demo`. |
| `SyntaxError: Cannot use import statement outside a module` | The file does not end in `.mjs`. | Rename it to `tool-permissions.mjs`. |
| `TOOL_UNAPPROVED` | `approveTool` was not called, or the tool was registered again afterwards. | Call `approveTool` with the fingerprint from the latest `registerTool`. |
| `ARGUMENT_INVALID` | `parse` rejected the arguments. | Send exactly `{ recordId: '...' }`. |
| `TASK_EXPIRED` | More than sixty seconds passed since `createTask`. | Run the script again. |
| `CALL_BUDGET_EXCEEDED` | The task already made its one call. | Raise `maxCalls`, or create a new task. |

## Use the pattern in your application

- **Give the model a dispatcher, not the guard.** Your code receives the model's
  tool request, picks the task for that conversation, and calls `prepare` and
  `execute`. The model never sees the guard object, the task handle or
  `approve`.
- **Take identity from your own data.** Here the tenant and the reviewer are
  fixed strings. In an application, read the tenant from your session or
  database and authenticate the reviewer before you call `approve`.
- **Check again where the effect happens.** The guard decides whether the
  handler runs. Your backend should still enforce who may change what.

The guard keeps its state in memory, and it has no effect on operations that do
not go through it. [Support and limits](../support-and-limits.md) lists what it
covers and what stays with you.

## Next steps

- [Delegation](delegation.md): hand part of a task to a sub-agent.
- [Audit log](audit-log.md): record every decision.
- [Package guide](../package-guide.md): add Model Context Protocol (MCP) tools or keep
  state across restarts.
- [API contract](../api-contract.md): every option and rule.
- The same example as one file with assertions:
  [`examples/tool-permissions.mjs`](../../examples/tool-permissions.mjs).
