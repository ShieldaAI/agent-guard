// What the durable executor keeps across a restart, and what has to be done again.
//
// Run: npm run build, then node examples/restart.mjs
// It writes an encrypted ledger to a temporary directory, "restarts" by closing and
// reopening it, and removes the directory at the end. Linux and macOS.
import { randomBytes } from 'node:crypto';
import { mkdtempSync, realpathSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DurableExecutor } from '@shieldaai/agent-guard-executor';

// The ledger's directory must belong to the service user, be closed to everyone else (mode
// 0700) and be named by its real path, with no symbolic link in it; otherwise the executor
// refuses to open it with STORE_DIRECTORY_UNSAFE. mkdtemp creates a 0700 directory, and
// realpath resolves links such as macOS's /var.
const directory = realpathSync(mkdtempSync(join(tmpdir(), 'agent-guard-example-')));
const database = join(directory, 'ledger.sqlite');
// 32 random bytes. A real service keeps this key in its secret store: without it the
// ledger cannot be read.
const encryptionKey = randomBytes(32);

const refund = {
  name: 'refund.send',
  description: 'Send one refund',
  requiresApproval: true,
  maxCost: 5,
  resolve: () => ({ resourceId: 'order-17', tenantId: 'acme' }),
  execute: () => ({ value: 'sent', actualCost: 3 }),
};

function start() {
  const executor = new DurableExecutor({ database, encryptionKey });
  // Tools are code, so every process registers and approves them again.
  executor.approveTool(refund.name, executor.registerTool(refund));
  return executor;
}
const approve = (executor, action) =>
  executor.approve(action.id, { approverId: 'reviewer-2', expiresAt: Date.now() + 300_000 });
const spent = executor => {
  const { calls, spent } = executor.snapshot('refund-task');
  return `${calls} ${calls === 1 ? 'call' : 'calls'}, ${spent} of 15 spent`;
};

try {
  // --- First process: one refund runs, a second one is approved but not yet run. ---
  let executor = start();
  executor.createTask({
    id: 'refund-task',
    principalId: 'user-7',
    tenantId: 'acme',
    grants: [{ tool: 'refund.send', resources: ['order-17'] }],
    budget: { maxCalls: 3, maxConcurrent: 1, maxCost: 15, deadline: Date.now() + 600_000 },
  });
  const first = await executor.prepare('refund-task', { tool: 'refund.send', args: {} });
  console.log(
    'before restart:',
    await executor.execute('refund-task', first.id, { approvalId: approve(executor, first) }),
  );
  const second = await executor.prepare('refund-task', { tool: 'refund.send', args: {} });
  const earlierApproval = approve(executor, second);
  console.log('before restart:', spent(executor));
  executor.close();

  // --- Second process: the same ledger file and key. ---
  executor = start();
  // Kept: the task, its budget and what it already spent (revocations and used approvals too).
  console.log('after restart: ', spent(executor));
  // Not kept: an action that was prepared or approved but had not run. It must be prepared
  // and reviewed again, so nothing approved under the old process runs unseen.
  try {
    await executor.execute('refund-task', second.id, { approvalId: earlierApproval });
  } catch (error) {
    console.log('after restart:  the earlier approval is refused:', error.code);
  }
  const again = await executor.prepare('refund-task', { tool: 'refund.send', args: {} });
  console.log(
    'after restart: ',
    await executor.execute('refund-task', again.id, { approvalId: approve(executor, again) }),
  );
  console.log('after restart: ', spent(executor));
  executor.close();
} finally {
  rmSync(directory, { recursive: true, force: true });
}
