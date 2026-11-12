import { isGuardError } from '@shieldaai/agent-guard';
import type { ScenarioId } from '../catalog.js';
import { CheckFailure, GUIDE, deferred, bounded, fixture, readGrant, type Checks, type Pair } from '../fixtures.js';

/** Bounded work: call, concurrency, cost and deadline limits (S10). */
export const budgetCases = {
  S10: {
    async malicious(c: Checks) {
      const f = fixture(c);
      const entered = deferred<void>();
      const release = deferred<void>();
      let hold = true;
      f.read({
        maxCost: 2,
        async execute() {
          c.handlerInvocations += 1;
          entered.resolve();
          if (hold) await release.promise;
          return { value: 'done', actualCost: 2 };
        },
      });
      const task = f.task(readGrant(), { budget: f.budget({ maxCalls: 3, maxConcurrent: 1, maxCost: 10 }) });
      const prepared = await Promise.all(
        Array.from({ length: 9 }, () => f.guard.prepare(task, { tool: 'read_document', args: { resource: GUIDE } })),
      );
      const first = f.guard.execute(prepared[0]!);
      try {
        await bounded(
          Promise.race([
            entered.promise,
            first.then(() => {
              throw new CheckFailure('held fixture completed too early');
            }),
          ]),
          'budget fixture not entered',
        );
        const snapshot = f.guard.snapshot(task);
        c.assert(
          snapshot.concurrent === 1 && snapshot.reserved === 2 && snapshot.calls === 1,
          'admission reserves concurrency, call and cost',
        );
        await Promise.all(
          prepared
            .slice(1)
            .map(action => c.denied(() => f.guard.execute(action), 'concurrent burst denial', 'CONCURRENCY_EXCEEDED')),
        );
        c.assert(c.handlerInvocations === 1, 'burst admits no second concurrent handler');
      } finally {
        hold = false;
        release.resolve();
      }
      await first;
      await f.invoke(task, 'read_document', { resource: GUIDE });
      await f.invoke(task, 'read_document', { resource: GUIDE });
      await c.denied(
        () => f.invoke(task, 'read_document', { resource: GUIDE }),
        'call budget exhaustion',
        'CALL_BUDGET_EXCEEDED',
      );
      c.assert(
        f.guard.snapshot(task).calls === 3 && f.guard.snapshot(task).spent === 6,
        'three admitted calls retain charges',
      );

      const shared = fixture(c);
      const sharedEntered = deferred<void>();
      const sharedRelease = deferred<void>();
      shared.read({
        maxCost: 3,
        async execute() {
          c.handlerInvocations += 1;
          sharedEntered.resolve();
          await sharedRelease.promise;
          return { value: 'done', actualCost: 3 };
        },
      });
      const parent = shared.task(readGrant(), { budget: shared.budget({ maxCost: 5 }) });
      const childOptions = { grants: readGrant(), budget: shared.budget({ maxCost: 5 }) };
      const childA = shared.guard.delegateTask(parent, { ...childOptions, id: 'child-a' });
      const childB = shared.guard.delegateTask(parent, { ...childOptions, id: 'child-b' });
      const sharedRunning = shared.invoke(childA, 'read_document', { resource: GUIDE });
      const sharedObserved = sharedRunning.then(
        () => undefined,
        () => undefined,
      );
      try {
        await bounded(
          Promise.race([
            sharedEntered.promise,
            sharedObserved.then(() => {
              throw new CheckFailure('shared cost fixture settled too early');
            }),
          ]),
          'shared cost fixture not entered',
        );
        c.assert(shared.guard.snapshot(parent).reserved === 3, 'ancestor reserves cost before child effect settles');
        await c.denied(
          () => shared.invoke(childB, 'read_document', { resource: GUIDE }),
          'siblings share outstanding ancestor reservation',
          'COST_BUDGET_EXCEEDED',
        );
      } finally {
        sharedRelease.resolve();
      }
      await sharedRunning;
      await c.denied(
        () => shared.invoke(childB, 'read_document', { resource: GUIDE }),
        'siblings share ancestor cost budget',
        'COST_BUDGET_EXCEEDED',
      );
      c.assert(shared.guard.snapshot(parent).spent === 3, 'ancestor accounts for child spending');

      const expired = fixture(c);
      expired.read();
      const expiredTask = expired.task(readGrant(), { budget: expired.budget({ deadline: 1100 }) });
      const beforeExpiry = await expired.guard.prepare(expiredTask, {
        tool: 'read_document',
        args: { resource: GUIDE },
      });
      expired.setTime(1100);
      await c.denied(() => expired.guard.execute(beforeExpiry), 'deadline at dispatch', 'TASK_EXPIRED');
      await c.denied(
        () => expired.invoke(expiredTask, 'read_document', { resource: GUIDE }),
        'deadline on new work',
        'TASK_EXPIRED',
      );

      const overrun = fixture(c);
      overrun.read({ maxCost: 2, execute: () => ({ ...c.effect('effect happened'), actualCost: 3 }) });
      const overrunTask = overrun.task(readGrant());
      let error: unknown;
      try {
        await overrun.invoke(overrunTask, 'read_document', { resource: GUIDE });
      } catch (caught) {
        error = caught;
      }
      c.assert(isGuardError(error), 'overrun cost report is rejected after effect');
      c.assert(overrun.guard.snapshot(overrunTask).spent === 2, 'overrun retains reserved charge');
      await c.denied(
        () => overrun.invoke(overrunTask, 'read_document', { resource: GUIDE }),
        'overrun revokes future authority',
        'TASK_REVOKED',
      );
    },
    async benign(c: Checks) {
      const f = fixture(c);
      f.read({ maxCost: 3, execute: () => ({ ...c.effect('done'), actualCost: 1 }) });
      const task = f.task(readGrant(), { budget: f.budget({ maxCalls: 3, maxConcurrent: 1, maxCost: 6 }) });
      await f.invoke(task, 'read_document', { resource: GUIDE });
      await f.invoke(task, 'read_document', { resource: GUIDE });
      const snapshot = f.guard.snapshot(task);
      c.assert(
        snapshot.calls === 2 && snapshot.concurrent === 0 && snapshot.spent === 2 && snapshot.reserved === 0,
        'completed work reconciles usage and releases slots',
      );

      const omitted = fixture(c);
      omitted.read({ maxCost: 3 });
      const omittedTask = omitted.task(readGrant(), { budget: omitted.budget({ maxCost: 6 }) });
      await omitted.invoke(omittedTask, 'read_document', { resource: GUIDE });
      await omitted.invoke(omittedTask, 'read_document', { resource: GUIDE });
      const omittedSnapshot = omitted.guard.snapshot(omittedTask);
      c.assert(
        omittedSnapshot.calls === 2 &&
          omittedSnapshot.spent === 6 &&
          omittedSnapshot.reserved === 0 &&
          omittedSnapshot.concurrent === 0,
        'omitted actual cost charges the full declared maximum',
      );

      const cancel = fixture(c);
      const entered = deferred<void>();
      let observed = false;
      cancel.read({
        execute: async (_args, { signal }) => {
          c.handlerInvocations += 1;
          entered.resolve();
          await new Promise<void>(resolve => {
            const abort = () => {
              observed = true;
              resolve();
            };
            if (signal.aborted) abort();
            else signal.addEventListener('abort', abort, { once: true });
          });
          return { value: 'cancelled' };
        },
      });
      const cancelTask = cancel.task(readGrant());
      const running = cancel.invoke(cancelTask, 'read_document', { resource: GUIDE });
      const settled = running.then(
        () => undefined,
        () => undefined,
      );
      await bounded(
        Promise.race([
          entered.promise,
          settled.then(() => {
            throw new CheckFailure('cancellable handler did not wait');
          }),
        ]),
        'cancellation fixture not entered',
      );
      cancel.guard.revokeTask(cancelTask);
      await bounded(settled, 'cooperative handler did not settle after revocation');
      c.assert(observed, 'running handler observes cancellation');
      c.assert(
        cancel.guard.snapshot(cancelTask).concurrent === 0 && cancel.guard.snapshot(cancelTask).calls === 1,
        'cancelled handler releases concurrency and retains attempt',
      );

      const deadline = fixture(c);
      const deadlineEntered = deferred<void>();
      let deadlineObserved = false;
      deadline.read({
        execute: async (_args, { signal }) => {
          c.handlerInvocations += 1;
          deadlineEntered.resolve();
          await new Promise<void>(resolve => {
            const abort = () => {
              deadlineObserved = true;
              resolve();
            };
            if (signal.aborted) abort();
            else signal.addEventListener('abort', abort, { once: true });
          });
          return { value: 'cancelled' };
        },
      });
      const deadlineTask = deadline.task(readGrant(), { budget: deadline.budget({ deadline: 1020 }) });
      const deadlineRun = deadline.invoke(deadlineTask, 'read_document', { resource: GUIDE });
      const deadlineSettled = deadlineRun.then(
        () => undefined,
        () => undefined,
      );
      await bounded(
        Promise.race([
          deadlineEntered.promise,
          deadlineSettled.then(() => {
            throw new CheckFailure('deadline fixture did not wait');
          }),
        ]),
        'deadline fixture not entered',
      );
      deadline.setTime(1020);
      await bounded(deadlineSettled, 'cooperative handler did not settle at deadline');
      c.assert(
        deadlineObserved && deadline.guard.snapshot(deadlineTask).concurrent === 0,
        'deadline signals cooperative cancellation and releases slot',
      );

      const failed = fixture(c);
      let first = true;
      failed.read({
        maxCost: 3,
        execute: () => {
          c.handlerInvocations += 1;
          if (first) {
            first = false;
            throw new Error('synthetic failure');
          }
          return { value: 'recovered' };
        },
      });
      const failedTask = failed.task(readGrant(), { budget: failed.budget({ maxConcurrent: 1, maxCost: 9 }) });
      let rejected = false;
      try {
        await failed.invoke(failedTask, 'read_document', { resource: GUIDE });
      } catch {
        rejected = true;
      }
      c.assert(
        rejected && failed.guard.snapshot(failedTask).calls === 1 && failed.guard.snapshot(failedTask).concurrent === 0,
        'failed handler counts attempt and releases concurrency',
      );
      c.assert(
        failed.guard.snapshot(failedTask).spent === 3 && failed.guard.snapshot(failedTask).reserved === 0,
        'failed handler retains the full declared charge',
      );
      c.assert(
        (await failed.invoke(failedTask, 'read_document', { resource: GUIDE })) === 'recovered',
        'next authorized call can use released slot',
      );
      c.assert(
        failed.guard.snapshot(failedTask).spent === 6 && failed.guard.snapshot(failedTask).concurrent === 0,
        'recovery retains both admitted charges and releases concurrency',
      );
    },
  },
} satisfies Partial<Record<ScenarioId, Pair>>;
