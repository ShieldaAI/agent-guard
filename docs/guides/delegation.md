# Delegation: hand part of a task to a sub-agent

When an agent hands work to a sub-agent, the sub-agent should get less
authority, not a copy of everything. `delegateTask` creates a child task that
can only hold the same or less than its parent.

## What you will achieve

A parent task that may read two reports, and a child task that may read one. You
will see the child refused on the other report, a too-wide child refused when it
is created, and the child stopped when the parent is revoked.

## Prerequisites

- Node.js 22 or later
- `npm install @shieldaai/agent-guard`
- The [tool-permissions walkthrough](tool-permissions.md), for tools, tasks and
  `prepare`/`execute`

## 1. Create the parent task

Save this as `delegation.mjs`. Each step adds a block to the end of the file.

```js
import { AgentGuard, isGuardError } from '@shieldaai/agent-guard';

const guard = new AgentGuard();
const fingerprint = guard.registerTool({
  name: 'report.read',
  description: 'Read one report',
  resolve: args => ({ resourceId: args.id, tenantId: 'acme' }),
  execute: args => ({ value: `Contents of ${args.id}` }),
});
guard.approveTool('report.read', fingerprint);

const parent = guard.createTask({
  id: 'research',
  principalId: 'user-7',
  tenantId: 'acme',
  grants: [{ tool: 'report.read', resources: ['report-1', 'report-2'] }],
  budget: { maxCalls: 10, maxConcurrent: 2, maxCost: 0, deadline: Date.now() + 60_000 },
});

const read = async (task, id) =>
  guard.execute(await guard.prepare(task, { tool: 'report.read', args: { id } }));
```

## 2. Delegate a narrower child

```js
// The child gets one of the two reports, three calls and the parent's deadline.
const child = guard.delegateTask(parent, {
  id: 'research-summary',
  grants: [{ tool: 'report.read', resources: ['report-1'] }],
  budget: { maxCalls: 3, maxConcurrent: 1, maxCost: 0, deadline: guard.snapshot(parent).budget.deadline },
});

console.log(await read(child, 'report-1'));
console.log('parent calls used:', guard.snapshot(parent).calls);
```

The child keeps the parent's principal and tenant; you cannot set them. Read the
parent's deadline from `snapshot` instead of computing a new one, so the child's
deadline is never later.

The child's call also counts against the parent's budget.

## 3. See the child refused outside its grant

```js
try {
  await read(child, 'report-2');
} catch (error) {
  if (!isGuardError(error)) throw error;
  console.log('child reads report-2:', error.code);
}
```

The parent may read `report-2`. The child may not.

## 4. See a too-wide child refused

```js
try {
  guard.delegateTask(parent, {
    id: 'research-too-wide',
    grants: [{ tool: 'report.read', resources: ['report-3'] }],
    budget: { maxCalls: 1, maxConcurrent: 1, maxCost: 0, deadline: guard.snapshot(parent).budget.deadline },
  });
} catch (error) {
  if (!isGuardError(error)) throw error;
  console.log('wider child:', error.code, error.detail);
}
```

`error.detail` names the limit the child exceeded.

## 5. Revoke the parent

```js
guard.revokeTask(parent);
try {
  await read(child, 'report-1');
} catch (error) {
  if (!isGuardError(error)) throw error;
  console.log('after revoking the parent:', error.code);
}
```

## What you should see

Run `node delegation.mjs`:

```text
Contents of report-1
parent calls used: 1
child reads report-2: GRANT_DENIED
wider child: DELEGATION_DENIED GRANT_EXCEEDS_PARENT
after revoking the parent: TASK_REVOKED
```

## Narrowing rules

A child is checked against its parent and every ancestor above it.

| The child's ... | must be ... | Otherwise `detail` is |
| --- | --- | --- |
| Grants | tools and resources every ancestor holds. An ancestor's `*` covers any resource; a child cannot ask for `*` unless every ancestor has it. | `GRANT_EXCEEDS_PARENT` |
| `allowedRecipients` | recipients every ancestor lists | `RECIPIENT_EXCEEDS_PARENT` |
| `allowControlPlane` | set only if every ancestor has it | `CONTROL_PLANE_EXCEEDS_PARENT` |
| `maxCalls`, `maxConcurrent`, `maxCost` | no larger than any ancestor's | `BUDGET_EXCEEDS_PARENT` |
| `deadline` | no later than any ancestor's | `DEADLINE_EXCEEDS_PARENT` |

The error code is always `DELEGATION_DENIED`. The detail never contains a value
from the request.

Beyond creation:

- **Budgets add up.** Every call by a child also uses the budget of each
  ancestor. Three children with `maxCalls: 3` under a parent with `maxCalls: 5`
  can make five calls between them.
- **Grants are checked on every call.** A call needs a grant in the child and in
  each ancestor.
- **Marks are shared.** A parent and all its descendants form one task family.
  When any of them reads private data or outside content, the mark applies to
  all of them.
- **Authority only narrows.** A task's grants cannot be changed after it is
  created. To give a sub-agent different authority, create a new child.

## Revocation

| Call | Effect |
| --- | --- |
| `revokeTask(parent)` | The parent and every descendant are stopped for good. New calls fail with `TASK_REVOKED`, and running handlers receive an abort signal. |
| `revokeTask(child)` | Only that child and its own descendants are stopped. The parent continues. |
| `retireTask(task)` | Revokes the task and frees its ID and memory. Use it for finished tasks in a long-running process. |

Revocation cannot undo a call that a remote service has already accepted.

## With the executor

The executor has the same rules. Tasks are named by ID, and each child gets its
own bearer token:

```js
import { randomBytes } from 'node:crypto';
import { DurableExecutor } from '@shieldaai/agent-guard-executor';

const executor = new DurableExecutor({ database: ':memory:', encryptionKey: randomBytes(32) });
const deadline = Date.now() + 60_000;
const parent = executor.createTask({
  id: 'research', principalId: 'user-7', tenantId: 'acme',
  grants: [{ tool: 'report.read', resources: ['report-1', 'report-2'] }],
  budget: { maxCalls: 10, maxConcurrent: 2, maxCost: 0, deadline },
});
const child = executor.delegateTask(parent.taskId, {
  id: 'research-summary',
  grants: [{ tool: 'report.read', resources: ['report-1'] }],
  budget: { maxCalls: 3, maxConcurrent: 1, maxCost: 0, deadline },
});
console.log(child.taskId, 'has its own token:', child.token !== parent.token);
executor.close();
```

Give the sub-agent only `child.token`. An agent that holds a task token can also
create a narrower child itself with `POST /v1/task/delegate`; the same rules
apply. Revoking the parent makes the child's token invalid.

## What can go wrong

| You see | Cause | Fix |
| --- | --- | --- |
| `DELEGATION_DENIED` | The child asked for more than an ancestor holds. | Read `error.detail` and narrow that field. |
| `DELEGATION_DENIED` with `DEADLINE_EXCEEDS_PARENT` | The child's deadline was computed with a later `Date.now()`. | Use `guard.snapshot(parent).budget.deadline`. |
| `DUPLICATE_TASK` | The child's `id` is already in use. | Give each task its own ID. `retireTask` frees an ID. |
| `TASK_REVOKED` or `TASK_EXPIRED` from `delegateTask` | The parent is revoked or past its deadline. | Delegate from a live task. |
| `CALL_BUDGET_EXCEEDED` on a child that has calls left | An ancestor's budget is used up. | Check `snapshot` of each ancestor. |

The exact rules are in the [API contract](../api-contract.md).
