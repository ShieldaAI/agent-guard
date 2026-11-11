import test from 'node:test';
import assert from 'node:assert/strict';
import { createDecipheriv, randomBytes } from 'node:crypto';
import { mkdtempSync, mkdirSync, readFileSync, realpathSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { DurableExecutor } from '../dist/index.js';
import { ExecutorError, LedgerStore } from '../dist/store.js';

const task = (id, tenantId = 'tenant') => ({
  id,
  tenantId,
  principalId: 'operator',
  grants: [{ tool: 'write', resources: ['record'] }],
  budget: { maxCalls: 20, maxConcurrent: 2, maxCost: 100, deadline: 100_000 },
});
const child = id => {
  const { tenantId, principalId, ...options } = task(id);
  return options;
};
const deferred = () => {
  let resolve;
  const promise = new Promise(done => {
    resolve = done;
  });
  return { promise, resolve };
};
function setup(t, extra = {}) {
  const directory = realpathSync(mkdtempSync(join(tmpdir(), 'guard-lifecycle-')));
  const data = join(directory, 'data');
  mkdirSync(data, { mode: 0o700 });
  const config = { database: join(data, 'ledger.sqlite'), encryptionKey: randomBytes(32), clock: () => 1000, ...extra };
  let executor = new DurableExecutor(config);
  t.after(() => {
    executor?.close();
    rmSync(directory, { recursive: true, force: true });
  });
  return {
    directory,
    config,
    get executor() {
      return executor;
    },
    close() {
      executor?.close();
      executor = undefined;
    },
    reopen() {
      executor = new DurableExecutor(config);
      return executor;
    },
  };
}
function register(executor, handler = () => ({ value: true, actualCost: 2 }), more = {}) {
  const fp = executor.registerTool({
    name: 'write',
    description: 'approved fixture change',
    maxCost: 5,
    resolve: (_args, identity) => ({ resourceId: 'record', tenantId: identity.tenantId }),
    execute: handler,
    ...more,
  });
  executor.approveTool('write', fp);
}
const scope = taskId => ({ tenantId: 'tenant', taskId });
function decide(executor, taskId) {
  const preview = executor.previewTaskFamilyRetirement(scope(taskId));
  return { ...scope(taskId), expectedDigest: preview.reviewDigest };
}
function retireAndArchive(executor, taskId) {
  executor.retireTaskFamily(decide(executor, taskId));
  return executor.archiveTaskFamily(decide(executor, taskId));
}
async function effect(executor, taskId, args = {}) {
  const action = await executor.prepare(taskId, { tool: 'write', args });
  return executor.execute(taskId, action.id);
}

test('whole-family archival preserves encrypted authority evidence and prevents reuse after restart', async t => {
  const f = setup(t);
  const e = f.executor;
  register(e);
  const parent = e.createTask(task('root'));
  const leaf = e.delegateTask('root', child('child'));
  e.createTask(task('handoff'), { sourceTaskId: 'child' });
  await effect(e, 'child', { private: 'archive-private-fixture-marker' });
  await effect(e, 'handoff');
  const preview = e.previewTaskFamilyRetirement(scope('child'));
  assert.equal(preview.familyId, 'root');
  assert.equal(preview.counts.tasks, 3);
  assert.equal(JSON.stringify(preview).includes('archive-private-fixture-marker'), false);
  assert.deepEqual(preview.retirementBlockers, []);
  assert.deepEqual(preview.archiveBlockers, ['FAMILY_NOT_RETIRED']);
  assert.throws(() => e.previewTaskFamilyRetirement({ tenantId: 'foreign', taskId: 'root' }), {
    code: 'LIFECYCLE_SCOPE_DENIED',
  });
  const receipt = retireAndArchive(e, 'child');
  assert.deepEqual({ ...receipt.rootUsage }, { calls: '2', spent: '4' });
  assert.equal(e.maintenanceStatistics({ tenantId: 'tenant' }).tasks, 0);
  assert.equal(e.maintenanceStatistics({ tenantId: 'tenant' }).archivedTasks, 3);
  for (const id of ['root', 'child', 'handoff']) {
    assert.throws(() => e.createTask(task(id)), { code: 'DUPLICATE_TASK' });
    assert.throws(() => e.createTask(task(id, 'foreign')), { code: 'DUPLICATE_TASK' });
    assert.equal(e.findTaskFamilyArchive(scope(id)).archiveId, receipt.archiveId);
  }
  assert.equal(e.findTaskFamilyArchive({ tenantId: 'foreign', taskId: 'root' }), null);
  assert.throws(() => e.authenticate(parent.token), { code: 'UNAUTHENTICATED' });
  assert.throws(() => e.authenticate(leaf.token), { code: 'UNAUTHENTICATED' });
  assert.throws(() => e.createTask(task('new-root'), { sourceTaskId: 'child' }), { code: 'INVALID_TASK' });
  f.close();
  assert.equal(readFileSync(f.config.database).includes(Buffer.from('archive-private-fixture-marker')), false);
  // Inspect actual retained evidence with the host's protected ledger, rather than
  // assuming that a successful archival response preserved counters and ancestry.
  const store = new LedgerStore(f.config.database, f.config.encryptionKey);
  const state = store.read(),
    entry = state.lifecycle.archives[receipt.archiveId];
  const [iv, tag, encrypted] = JSON.parse(store.readArchive(receipt.archiveId));
  const cipher = createDecipheriv('aes-256-gcm', Buffer.from(entry.keyBase64, 'base64'), Buffer.from(iv, 'base64'));
  cipher.setAAD(
    Buffer.from(
      JSON.stringify(['agent-guard-family-archive-v1', state.inventoryInstanceId, receipt.archiveId, 'tenant']),
    ),
  );
  cipher.setAuthTag(Buffer.from(tag, 'base64'));
  const archived = JSON.parse(Buffer.concat([cipher.update(Buffer.from(encrypted, 'base64')), cipher.final()]));
  assert.equal(archived.tasks.child.parent, 'root');
  assert.equal(archived.tasks.handoff.sourceTaskId, 'child');
  assert.equal(archived.tasks.root.spent, 2);
  assert.equal(archived.tasks.child.spent, 2);
  assert.deepEqual(archived.tasks.root.options.budget, task('root').budget);
  assert(Object.values(archived.tasks).every(value => value.revoked));
  assert.equal(
    Object.values(archived.actions).find(action => action.taskId === 'child').action.args.private,
    'archive-private-fixture-marker',
  );
  store.close();
  const reopened = f.reopen();
  assert.deepEqual(reopened.findTaskFamilyArchive(scope('handoff')), receipt);
  assert.throws(() => reopened.createTask(task('root')), { code: 'DUPLICATE_TASK' });
  assert.equal(reopened.createTask(task('fresh')).taskId, 'fresh');
});

test('archival frees live task capacity repeatedly while retaining bounded non-reusable identities', t => {
  const f = setup(t, { maxRecords: 4 });
  const e = f.executor;
  for (let i = 0; i < 4; i++) e.createTask(task(`initial-${i}`));
  assert.throws(() => e.createTask(task('overflow')), { code: 'CAPACITY_EXCEEDED' });
  for (let i = 0; i < 4; i++) retireAndArchive(e, `initial-${i}`);
  for (let i = 0; i < 20; i++) {
    e.createTask(task(`cycle-${i}`));
    retireAndArchive(e, `cycle-${i}`);
  }
  const statistics = e.maintenanceStatistics({ tenantId: 'tenant' });
  assert.equal(statistics.tasks, 0);
  assert.equal(statistics.archives, 24);
  assert.equal(statistics.archivedTasks, 24);
  assert.equal(statistics.retentionLimits.archivedIdentifiers, 65_536);
  f.close();
  f.reopen();
  assert.throws(() => f.executor.createTask(task('initial-0')), { code: 'DUPLICATE_TASK' });
});

test('active or uncertain effects block retirement until settlement or evidenced reconciliation', async t => {
  const f = setup(t),
    e = f.executor,
    entered = deferred(),
    release = deferred();
  register(e, async () => {
    entered.resolve();
    await release.promise;
    return { value: true, actualCost: 2 };
  });
  const credential = e.createTask(task('running'));
  const execution = effect(e, 'running');
  await entered.promise;
  const current = e.previewTaskFamilyRetirement(scope('running'));
  assert(current.retirementBlockers.includes('FAMILY_ACTIVE_WORK'));
  assert.throws(() => e.retireTaskFamily({ ...scope('running'), expectedDigest: current.reviewDigest }), {
    code: 'FAMILY_ACTIVE_WORK',
  });
  assert.equal(e.authenticate(credential.token), 'running');
  release.resolve();
  await execution;
  assert.throws(() => e.retireTaskFamily({ ...scope('running'), expectedDigest: current.reviewDigest }), {
    code: 'LIFECYCLE_PREVIEW_STALE',
  });
  retireAndArchive(e, 'running');
  register(e, () => {
    throw new Error('fixture lost backend response');
  });
  e.createTask(task('uncertain'));
  const action = await e.prepare('uncertain', { tool: 'write', args: {} });
  await assert.rejects(e.execute('uncertain', action.id), { code: 'TOOL_FAILED' });
  assert(e.previewTaskFamilyRetirement(scope('uncertain')).archiveBlockers.includes('FAMILY_UNRESOLVED_WORK'));
  assert.throws(() => e.retireTaskFamily(decide(e, 'uncertain')), { code: 'FAMILY_ACTIVE_WORK' });
  e.reconcile(action.id, { outcome: 'SUCCEEDED', actualCost: 2, reference: 'fixture backend ended receipt' });
  assert.equal(retireAndArchive(e, 'uncertain').rootUsage.spent, '2');
});

test('retirement cancels prepared approval and pending policy without permitting a late effect', async t => {
  const entered = deferred(),
    release = deferred();
  let stall = false,
    effects = 0;
  const f = setup(t, {
    policy: async () => {
      if (stall) {
        entered.resolve();
        await release.promise;
      }
      return 'allow';
    },
  });
  const e = f.executor;
  register(e, () => ({ value: ++effects }), { requiresApproval: true });
  e.createTask(task('task'));
  const action = await e.prepare('task', { tool: 'write', args: {} });
  const approvalId = e.approve(action.id, { approverId: 'host-reviewer', expiresAt: 3000 });
  stall = true;
  const pending = e.prepare('task', { tool: 'write', args: {} });
  await entered.promise;
  const rejected = assert.rejects(pending, { code: 'TASK_REVOKED' });
  e.retireTaskFamily(decide(e, 'task'));
  assert.equal(e.execution('task', action.id).status, 'FAILED');
  await assert.rejects(e.execute('task', action.id, { approvalId }), { code: 'ACTION_USED' });
  e.archiveTaskFamily(decide(e, 'task'));
  release.resolve();
  await rejected;
  assert.equal(effects, 0);
});

test('family reviews become stale on mutation and archived commits cannot be replayed', t => {
  const f = setup(t),
    e = f.executor;
  e.createTask(task('task'));
  assert.throws(() => e.archiveTaskFamily(decide(e, 'task')), { code: 'FAMILY_NOT_RETIRED' });
  const before = decide(e, 'task');
  e.createTask(task('other'));
  assert.throws(() => e.retireTaskFamily(before), { code: 'LIFECYCLE_PREVIEW_STALE' });
  e.retireTaskFamily(decide(e, 'task'));
  const archive = decide(e, 'task');
  e.archiveTaskFamily(archive);
  assert.throws(() => e.archiveTaskFamily(archive), { code: 'LIFECYCLE_PREVIEW_STALE' });
  assert.equal(e.maintenanceStatistics({ tenantId: 'tenant' }).archives, 1);
});

test('residual identity capacity fails closed without evicting retired authority', t => {
  const f = setup(t),
    e = f.executor;
  e.createTask(task('task'));
  e.retireTaskFamily(decide(e, 'task'));
  f.close();
  const store = new LedgerStore(f.config.database, f.config.encryptionKey);
  store.transaction(state => {
    state.lifecycle.archivedMemoryIds = Array.from({ length: 65_536 }, (_, index) =>
      index.toString(16).padStart(64, '0'),
    );
  });
  store.close();
  const reopened = f.reopen();
  assert(reopened.previewTaskFamilyRetirement(scope('task')).archiveBlockers.includes('ARCHIVE_CAPACITY_EXCEEDED'));
  assert.throws(() => reopened.archiveTaskFamily(decide(reopened, 'task')), { code: 'ARCHIVE_CAPACITY_EXCEEDED' });
  assert.equal(reopened.snapshot('task').calls, 0);
  assert.equal(reopened.maintenanceStatistics({ tenantId: 'tenant' }).archives, 0);
});

test('mixed ownership of one memory history cannot be discarded with either family', async t => {
  const f = setup(t),
    e = f.executor;
  const registered = e.registerMemoryTools();
  for (const [name, fp] of Object.entries(registered)) e.approveTool(`memory.${name}`, fp);
  for (const id of ['first', 'second'])
    e.createTask({ ...task(id), grants: [{ tool: 'memory.write', resources: ['shared'] }] });
  for (const [id, version] of [
    ['first', 0],
    ['second', 1],
  ]) {
    const action = await e.prepare(id, { tool: 'memory.write', args: { id: 'shared', value: id, ifVersion: version } });
    await e.execute(id, action.id);
  }
  for (const id of ['first', 'second']) {
    e.retireTaskFamily(decide(e, id));
    assert.throws(() => e.archiveTaskFamily(decide(e, id)), { code: 'FAMILY_EXTERNAL_REFERENCE' });
  }
  assert.equal(e.maintenanceStatistics({ tenantId: 'tenant' }).memoryEntries, 1);
});

test('external memory references block archive and archived memory names cannot lose their labels through reuse', async t => {
  const f = setup(t),
    e = f.executor;
  const registered = e.registerMemoryTools();
  for (const [name, fingerprint] of Object.entries(registered)) e.approveTool(`memory.${name}`, fingerprint);
  const memoryTask = (id, tenantId = 'tenant') => ({
    ...task(id, tenantId),
    grants: [
      { tool: 'memory.read', resources: ['shared'] },
      { tool: 'memory.write', resources: ['shared'] },
    ],
  });
  e.createTask(memoryTask('writer'));
  e.createTask(memoryTask('reader'));
  const call = async (taskId, tool, args) => e.execute(taskId, (await e.prepare(taskId, { tool, args })).id);
  await call('writer', 'memory.write', { id: 'shared', value: 'restricted fixture', ifVersion: 0 });
  await call('reader', 'memory.read', { id: 'shared' });
  e.retireTaskFamily(decide(e, 'writer'));
  assert(e.previewTaskFamilyRetirement(scope('writer')).archiveBlockers.includes('FAMILY_EXTERNAL_REFERENCE'));
  assert.throws(() => e.archiveTaskFamily(decide(e, 'writer')), { code: 'FAMILY_EXTERNAL_REFERENCE' });
  retireAndArchive(e, 'reader');
  const receipt = e.archiveTaskFamily(decide(e, 'writer'));
  assert.equal(receipt.counts.memoryEntries, 1);
  e.createTask(memoryTask('fresh'));
  await assert.rejects(call('fresh', 'memory.write', { id: 'shared', value: 'unlabeled replacement', ifVersion: 0 }), {
    code: 'RESOLUTION_FAILED',
  });
  assert.throws(
    () =>
      e.importMemory({ tenantId: 'tenant', id: 'shared', origin: 'operator', value: 'replacement', sensitive: false }),
    { code: 'MEMORY_UNAVAILABLE' },
  );
  e.importMemory({ tenantId: 'other', id: 'shared', origin: 'operator', value: 'separate tenant', sensitive: false });
  assert.equal(e.maintenanceStatistics({ tenantId: 'other' }).memoryEntries, 1);
});

test('archive persistence failure rolls back the ciphertext and live-state deletion together', t => {
  const f = setup(t),
    e = f.executor;
  e.createTask(task('task'));
  e.retireTaskFamily(decide(e, 'task'));
  const before = decide(e, 'task'),
    original = LedgerStore.prototype.transaction;
  let attemptedId;
  LedgerStore.prototype.transaction = function (operation) {
    return original.call(this, (state, archives) =>
      operation(state, {
        ...archives,
        putArchive(id, bytes) {
          attemptedId = id;
          archives.putArchive(id, bytes);
          throw new ExecutorError('FIXTURE_ARCHIVE_COMMIT_FAILED');
        },
      }),
    );
  };
  try {
    assert.throws(() => e.archiveTaskFamily(before), { code: 'FIXTURE_ARCHIVE_COMMIT_FAILED' });
  } finally {
    LedgerStore.prototype.transaction = original;
  }
  assert.equal(e.maintenanceStatistics({ tenantId: 'tenant' }).tasks, 1);
  assert.equal(e.findTaskFamilyArchive(scope('task')), null);
  assert.equal(e.snapshot('task').spent, 0);
  f.close();
  const store = new LedgerStore(f.config.database, f.config.encryptionKey);
  assert.throws(() => store.readArchive(attemptedId), { code: 'STORE_ARCHIVE_UNAVAILABLE' });
  store.close();
  f.reopen();
  assert.equal(f.executor.archiveTaskFamily(decide(f.executor, 'task')).counts.tasks, 1);
});

test('archive verification detects missing/substituted ciphertext without releasing ID tombstones', t => {
  const f = setup(t),
    e = f.executor;
  e.createTask(task('task'));
  const receipt = retireAndArchive(e, 'task');
  f.close();
  const db = new DatabaseSync(f.config.database);
  db.prepare('UPDATE authority_archives SET payload=? WHERE id=?').run('substituted fixture', receipt.archiveId);
  db.close();
  const reopened = f.reopen();
  assert.throws(() => reopened.verifyTaskFamilyArchive({ tenantId: 'tenant', archiveId: receipt.archiveId }), {
    code: 'ARCHIVE_INVALID',
  });
  assert.throws(() => reopened.findTaskFamilyArchive(scope('task')), { code: 'ARCHIVE_INVALID' });
  assert.throws(() => reopened.createTask(task('task')), { code: 'DUPLICATE_TASK' });
  assert.throws(() => reopened.verifyTaskFamilyArchive({ tenantId: 'foreign', archiveId: receipt.archiveId }), {
    code: 'LIFECYCLE_SCOPE_DENIED',
  });
});

test('execution listing is tenant-scoped, bounded, cursor-bound and excludes arguments', async t => {
  const f = setup(t),
    e = f.executor;
  register(e, () => {
    throw new Error('fixture uncertain');
  });
  for (const id of ['a', 'b', 'foreign']) {
    e.createTask(task(id, id === 'foreign' ? 'foreign' : 'tenant'));
    await assert.rejects(effect(e, id, { secret: 'not-for-maintenance-list' }), { code: 'TOOL_FAILED' });
  }
  const first = e.listExecutions({ tenantId: 'tenant', limit: 1 });
  assert.equal(first.total, 2);
  assert.equal(first.items.length, 1);
  assert(first.nextCursor);
  assert.equal(JSON.stringify(first).includes('not-for-maintenance-list'), false);
  const next = e.listExecutions({ tenantId: 'tenant', limit: 1, cursor: first.nextCursor });
  assert.equal(next.items.length, 1);
  assert.equal(next.nextCursor, null);
  assert.notEqual(first.items[0].actionId, next.items[0].actionId);
  assert.throws(() => e.listExecutions({ tenantId: 'foreign', cursor: first.nextCursor }), {
    code: 'LIFECYCLE_CURSOR_INVALID',
  });
  assert.throws(() => e.listExecutions({ tenantId: 'tenant', limit: 101 }), { code: 'LIFECYCLE_SCOPE_INVALID' });
  assert.throws(() => e.listExecutions({ tenantId: 'tenant', cursor: first.nextCursor + '.extra' }), {
    code: 'LIFECYCLE_CURSOR_INVALID',
  });
  e.reconcile(first.items[0].actionId, { outcome: 'FAILED', actualCost: 0, reference: 'fixture no backend effect' });
  assert.throws(() => e.listExecutions({ tenantId: 'tenant', cursor: first.nextCursor }), {
    code: 'LIFECYCLE_CURSOR_STALE',
  });
  assert.equal(e.maintenanceStatistics({ tenantId: 'foreign' }).unresolvedActions, 1);
});

test(
  'a witnessed archive cannot be undone by restoring pre-archive authority',
  { skip: process.platform === 'win32' },
  t => {
    const f = setup(t);
    f.close();
    const control = join(f.directory, 'control');
    mkdirSync(control, { mode: 0o700 });
    // Provision a fresh witnessed pair; the ordinary fixture ledger is never upgraded in place.
    f.config.database = join(f.directory, 'data', 'witnessed.sqlite');
    f.config.rollbackWitness = { path: join(control, 'latest.sqlite'), mode: 'create' };
    let e = f.reopen();
    e.createTask(task('task'));
    e.retireTaskFamily(decide(e, 'task'));
    f.close();
    const old = readFileSync(f.config.database);
    f.config.rollbackWitness.mode = 'resume';
    e = f.reopen();
    e.archiveTaskFamily(decide(e, 'task'));
    f.close();
    writeFileSync(f.config.database, old);
    assert.throws(() => f.reopen(), { code: 'STORE_WITNESS_UNAVAILABLE' });
  },
);
