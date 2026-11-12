import type { Policy } from '@shieldaai/agent-guard';
import type { ScenarioId } from '../catalog.js';
import {
  CheckFailure,
  GUIDE,
  PAYROLL,
  RECORD_A,
  RECIPIENT,
  OTHER_RECIPIENT,
  deferred,
  bounded,
  fixture,
  readGrant,
  deleteGrant,
  type Checks,
  type Pair,
} from '../fixtures.js';

/** Authority over time: delegation to child tasks (S02) and rechecks before dispatch (S08). */
export const delegationCases = {
  S02: {
    async malicious(c: Checks) {
      const f = fixture(c);
      f.read();
      f.remove({ requiresApproval: false });
      const parent = f.task(readGrant(), { allowedRecipients: [RECIPIENT] });
      const childOptions = { id: 'child', grants: readGrant(), budget: f.budget(), allowedRecipients: [RECIPIENT] };
      const child = f.guard.delegateTask(parent, childOptions);
      await c.denied(
        () => f.guard.delegateTask(parent, { ...childOptions, id: 'wider-tool', grants: deleteGrant() }),
        'delegated tool widening',
        'DELEGATION_DENIED',
      );
      await c.denied(
        () => f.guard.delegateTask(child, { ...childOptions, id: 'wider-resource', grants: readGrant('*') }),
        'grandchild resource widening',
        'DELEGATION_DENIED',
      );
      await c.denied(
        () =>
          f.guard.delegateTask(parent, {
            ...childOptions,
            id: 'wider-recipient',
            allowedRecipients: [OTHER_RECIPIENT],
          }),
        'delegated recipient widening',
        'DELEGATION_DENIED',
      );
      await c.denied(
        () => f.guard.delegateTask(parent, { ...childOptions, id: 'wider-control', allowControlPlane: true }),
        'delegated control-plane widening',
        'DELEGATION_DENIED',
      );
      await c.denied(
        () => f.guard.delegateTask(parent, { ...childOptions, id: 'wider-budget', budget: f.budget({ maxCalls: 31 }) }),
        'delegated budget widening',
        'DELEGATION_DENIED',
      );
      await c.denied(
        () => f.invoke(child, 'delete_record', { resource: RECORD_A, parentId: 'admin-task' }),
        'child write without authority',
        'GRANT_DENIED',
      );
      await c.denied(
        () => f.invoke(child, 'read_document', { resource: PAYROLL, parentId: 'admin-task' }),
        'claimed parent cannot widen authority',
        'GRANT_DENIED',
      );
      f.guard.revokeTask(parent);
      await c.denied(
        () => f.invoke(child, 'read_document', { resource: GUIDE }),
        'ancestor revocation',
        'TASK_REVOKED',
      );
    },
    async benign(c: Checks) {
      const f = fixture(c);
      f.read();
      const parent = f.task([{ tool: 'read_document', resources: [GUIDE, PAYROLL] }]);
      const child = f.guard.delegateTask(parent, {
        id: 'child',
        grants: readGrant(),
        budget: f.budget({ maxCalls: 2 }),
      });
      await f.invoke(child, 'read_document', { resource: GUIDE });
      const snapshot = f.guard.snapshot(child);
      c.assert(snapshot.principalId === 'user-1' && snapshot.tenantId === 'alpha', 'child inherits trusted identity');
      c.assert(
        snapshot.calls === 1 && f.guard.snapshot(parent).calls === 1,
        'child admission charges parent and child',
      );
      c.assert(c.handlerInvocations === 1, 'one permitted child effect');
    },
  },
  S08: {
    async malicious(c: Checks) {
      for (const change of ['revoke', 'policy'] as const) {
        const entered = deferred<void>();
        const release = deferred<void>();
        let wait = false;
        const f = fixture(c, {
          policy: async () => {
            if (wait) {
              entered.resolve();
              await release.promise;
            }
            return 'allow' as const;
          },
        });
        f.remove();
        const task = f.task(deleteGrant());
        const prepared = await f.guard.prepare(task, { tool: 'delete_record', args: { resource: RECORD_A } });
        const approvalId = f.approve(prepared);
        wait = true;
        await c.denied(
          async () => {
            const pending = f.guard.execute(prepared, { approvalId });
            // Observe early settlement immediately, including when testing a broken implementation.
            const observed = pending.then(
              () => undefined,
              () => undefined,
            );
            try {
              await bounded(
                Promise.race([
                  entered.promise,
                  observed.then(() => {
                    throw new CheckFailure('execution settled before policy barrier');
                  }),
                ]),
                'policy barrier not reached',
              );
              if (change === 'revoke') f.guard.revokeTask(task);
              else f.guard.setPolicy(() => 'allow');
            } finally {
              release.resolve();
            }
            return pending;
          },
          `${change} during asynchronous policy`,
          change === 'revoke' ? 'TASK_REVOKED' : 'POLICY_CHANGED',
        );
        c.assert(f.ledger.length === 0, `${change} during asynchronous policy leaves the ledger empty`);
      }
      const f = fixture(c);
      f.remove();
      const task = f.task(deleteGrant());
      await c.denied(
        () => f.invoke(task, 'delete_record', { resource: RECORD_A }),
        'missing independent approval',
        'APPROVAL_REQUIRED',
      );
      for (const policy of [
        (() => 'invalid') as unknown as Policy,
        (() => {
          throw new Error('fixture policy failure');
        }) as Policy,
      ]) {
        const invalid = fixture(c, { policy });
        invalid.read();
        await c.denied(
          () => invalid.invoke(invalid.task(readGrant()), 'read_document', { resource: GUIDE }),
          'invalid required policy',
          'POLICY_ERROR',
        );
      }
      const permissive = fixture(c, { policy: () => 'allow' });
      permissive.read();
      await c.denied(
        () => permissive.invoke(permissive.task(readGrant()), 'read_document', { resource: PAYROLL }),
        'custom allow cannot bypass grants',
        'GRANT_DENIED',
      );
    },
    async benign(c: Checks) {
      const f = fixture(c, { policy: async () => 'require_approval' as const });
      f.read();
      const task = f.task(readGrant());
      const prepared = await f.guard.prepare(task, { tool: 'read_document', args: { resource: GUIDE } });
      c.assert(prepared.requiresApproval, 'custom policy may tighten to approval');
      await f.guard.execute(prepared, { approvalId: f.approve(prepared) });
      c.assert(
        c.handlerInvocations === 1 && f.guard.snapshot(task).calls === 1,
        'live current approval permits one read',
      );
    },
  },
} satisfies Partial<Record<ScenarioId, Pair>>;
