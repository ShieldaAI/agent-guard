// Synthetic projection fixture; no company records, credentials or authority.
export const now = 1793980800000;
export function fixture() {
  const ledger = {
    schema: 1,
    revision: 1310,
    epoch: 10,
    lastClock: now,
    inventoryInstanceId: '00000000-0000-4000-8000-000000000001',
    tasks: {},
    families: {},
    tools: {},
    actions: {},
    approvals: {},
    memory: {},
    audit: [],
  };
  for (let i = 0; i < 10; i++)
    ledger.tools[`synthetic.read-${i}`] = { fingerprint: 'a'.repeat(64), revision: 1, approved: true };
  for (let i = 0; i < 100; i++) {
    const id = `synthetic-task-${i}`,
      family = `synthetic-family-${i}`;
    ledger.tasks[id] = {
      options: {
        id,
        tenantId: 'synthetic-admission',
        principalId: `synthetic-agent-${i}`,
        grants: Array.from({ length: 10 }, (_, j) => ({
          tool: `synthetic.read-${j}`,
          resources: ['synthetic-record'],
        })),
        budget: { maxCalls: 301, maxConcurrent: 1, maxCost: 0, deadline: now + 3600000 },
        allowedRecipients: [],
      },
      parent: null,
      family,
      tokenHash: 'b'.repeat(64),
      revoked: false,
      calls: i === 0 ? 300 : 0,
      concurrent: 0,
      spent: 0,
      reserved: 0,
    };
    ledger.families[family] = { sensitive: false };
  }
  for (let i = 0; i < 300; i++) {
    const id = `00000000-0000-4000-8000-${String(i).padStart(12, '0')}`;
    ledger.actions[id] = {
      id,
      taskId: 'synthetic-task-0',
      action: {
        tool: 'synthetic.read-0',
        args: { value: i },
        resourceId: 'synthetic-record',
        tenantId: 'synthetic-admission',
        sensitive: false,
        controlPlane: false,
        toolFingerprint: 'a'.repeat(64),
        policyVersion: 10,
      },
      digest: 'sha256:' + 'c'.repeat(64),
      toolRevision: 1,
      requiresApproval: false,
      status: 'SUCCEEDED',
      maxCost: 0,
      charged: 0,
    };
    for (const event of ['ACTION_PREPARED', 'ACTION_ADMITTED', 'ACTION_RUNNING', 'ACTION_SUCCEEDED'])
      ledger.audit.push({ time: now + i, event, taskId: 'synthetic-task-0', actionId: id });
  }

  return ledger;
}

export function uniqueFixture() {
  const state = fixture();
  for (let i = 0; i < 100; i++) {
    const task = state.tasks[`synthetic-task-${i}`];
    task.options.grants.forEach((g, j) => {
      g.resources = [`unique-${i}-${j}-雪😀`];
    });
    task.options.allowedRecipients = [`recipient-${i}-雪😀`];
  }
  return state;
}
