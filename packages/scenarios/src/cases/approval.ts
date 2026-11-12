import { isGuardError } from '@shieldaai/agent-guard';
import type { ScenarioId } from '../catalog.js';
import { RECORD_A, RECORD_B, fields, fixture, deleteGrant, type Checks, type Pair } from '../fixtures.js';

/** Human approval: exact single-use approvals (S05) and approvals bound to resource versions (S12). */
export const approvalCases = {
  S05: {
    async malicious(c: Checks) {
      const f = fixture(c);
      f.remove();
      const task = f.task(deleteGrant());
      const callerArgs = { resource: RECORD_A, details: { reason: 'Reviewed' } };
      const original = await f.guard.prepare(task, { tool: 'delete_record', args: callerArgs });
      const approvalId = f.approve(original);
      callerArgs.resource = RECORD_B;
      callerArgs.details.reason = 'Changed after review';
      const changed = await f.guard.prepare(task, { tool: 'delete_record', args: callerArgs });
      await c.denied(
        () => f.guard.execute(changed, { approvalId }),
        'approval cannot transfer to a changed action',
        'APPROVAL_INVALID',
      );
      c.assert(
        fields(original.action.args).resource === RECORD_A,
        'prepared arguments are detached from caller mutation',
      );
      c.assert(
        Object.isFrozen(original.action.args) && Object.isFrozen(fields(original.action.args).details),
        'prepared nested arguments are frozen',
      );
      const concurrent = await Promise.allSettled(
        Array.from({ length: 8 }, () => f.guard.execute(original, { approvalId })),
      );
      c.assert(
        concurrent.filter(entry => entry.status === 'fulfilled').length === 1,
        'exactly one concurrent approved dispatch',
      );
      c.assert(
        concurrent.filter(entry => entry.status === 'rejected' && isGuardError(entry.reason)).length === 7,
        'replays return structured rejection',
      );
      c.assert(
        f.ledger.length === 1 && f.ledger[0] === `delete:${RECORD_A}`,
        'caller mutation never changes executed target',
      );
      const expired = await f.guard.prepare(task, { tool: 'delete_record', args: { resource: RECORD_A } });
      const expiredId = f.approve(expired, 1100);
      f.setTime(1100);
      await c.denied(
        () => f.guard.execute(expired, { approvalId: expiredId }),
        'approval expiry is checked at consumption',
        'APPROVAL_EXPIRED',
      );
      const revoked = await f.guard.prepare(task, { tool: 'delete_record', args: { resource: RECORD_A } });
      const revokedId = f.approve(revoked);
      f.guard.revokeTask(task);
      await c.denied(
        () => f.guard.execute(revoked, { approvalId: revokedId }),
        'approved task revocation',
        'TASK_REVOKED',
      );
    },
    async benign(c: Checks) {
      const f = fixture(c);
      f.remove();
      const task = f.task(deleteGrant(RECORD_A));
      const prepared = await f.guard.prepare(task, { tool: 'delete_record', args: { resource: RECORD_A } });
      c.assert(prepared.requiresApproval, 'destructive action requests approval');
      await f.guard.execute(prepared, { approvalId: f.approve(prepared) });
      c.assert(f.ledger.length === 1 && f.ledger[0] === `delete:${RECORD_A}`, 'approved exact target is deleted once');
    },
  },
  S12: {
    async malicious(c: Checks) {
      const f = fixture(c);
      let version = 'v1';
      f.register({
        name: 'versioned_write',
        description: 'Compare and write one synthetic record',
        requiresApproval: true,
        resolve: () => ({ resourceId: RECORD_A, tenantId: 'alpha', resourceVersion: version }),
        execute(_args, { action }) {
          c.handlerInvocations++;
          if (action.resourceVersion !== version) throw new Error('synthetic version conflict');
          f.ledger.push(`write:${version}`);
          return { value: version };
        },
      });
      const task = f.task([{ tool: 'versioned_write', resources: [RECORD_A] }]);
      const old = await f.guard.prepare(task, { tool: 'versioned_write', args: null });
      const approvalId = f.approve(old);
      c.assert(
        old.action.resourceVersion === 'v1' && Object.isFrozen(old.action),
        'resolved version is immutable approved action data',
      );
      await c.denied(
        () => f.guard.execute({ ...old, action: { ...old.action, resourceVersion: 'v2' } }, { approvalId }),
        'forged resource version',
        'INVALID_PREPARED',
      );
      version = 'v2';
      const fresh = await f.guard.prepare(task, { tool: 'versioned_write', args: null });
      c.assert(
        fresh.action.resourceVersion === 'v2' && fresh.digest !== old.digest,
        'new resource version receives a distinct prepared invocation',
      );
      await c.denied(
        () => f.guard.execute(fresh, { approvalId }),
        'approval transfer to new version',
        'APPROVAL_INVALID',
      );
      let error: unknown;
      try {
        await f.guard.execute(old, { approvalId });
      } catch (caught) {
        error = caught;
      }
      c.assert(
        isGuardError(error) && error.code === 'TOOL_FAILED',
        'stale resource compare fails with a sanitized handler error',
      );
      c.denialCodes.push('TOOL_FAILED');
      c.assert(
        c.handlerInvocations === 1 && f.ledger.length === 0,
        'stale attempt enters the handler but produces no effect',
      );
      await c.denied(() => f.guard.execute(old, { approvalId }), 'stale attempt cannot replay', 'ACTION_USED');
      c.assert(f.guard.snapshot(task).calls === 1, 'stale admitted attempt still consumes one call');
    },
    async benign(c: Checks) {
      const f = fixture(c);
      let version = 'v1';
      f.register({
        name: 'versioned_write',
        description: 'Compare and write one synthetic record',
        requiresApproval: true,
        resolve: () => ({ resourceId: RECORD_A, tenantId: 'alpha', resourceVersion: version }),
        execute(_args, { action }) {
          c.handlerInvocations++;
          if (action.resourceVersion !== version) throw new Error('synthetic version conflict');
          f.ledger.push(`write:${version}`);
          version = version === 'v1' ? 'v2' : 'v3';
          return { value: { version } };
        },
      });
      const task = f.task([{ tool: 'versioned_write', resources: [RECORD_A] }]);
      for (const expected of ['v1', 'v2']) {
        const prepared = await f.guard.prepare(task, { tool: 'versioned_write', args: null });
        c.assert(prepared.action.resourceVersion === expected, 'preparation binds the current resource version');
        const approvalId = f.approve(prepared);
        await f.guard.execute(prepared, { approvalId });
      }
      c.assert(
        c.handlerInvocations === 2 && f.ledger.join(',') === 'write:v1,write:v2',
        'each reviewed version produces exactly one intended effect',
      );
      c.assert(
        version === 'v3' && f.guard.snapshot(task).calls === 2,
        'two independent approvals advance the synthetic resource twice',
      );
    },
  },
} satisfies Partial<Record<ScenarioId, Pair>>;
