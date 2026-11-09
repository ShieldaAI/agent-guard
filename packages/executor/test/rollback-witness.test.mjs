import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import {
  chmodSync,
  closeSync,
  existsSync,
  linkSync,
  mkdirSync,
  mkdtempSync,
  openSync,
  readFileSync,
  realpathSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { dirname, join } from 'node:path';
import { tmpdir } from 'node:os';
import { DurableExecutor } from '../dist/index.js';

const posix = { skip: process.platform === 'win32' };
function fixture(t) {
  const dir = realpathSync(mkdtempSync(join(tmpdir(), 'guard-witness-')));
  const data = join(dir, 'data'),
    control = join(dir, 'control');
  mkdirSync(data, { mode: 0o700 });
  mkdirSync(control, { mode: 0o700 });
  const database = join(data, 'ledger.sqlite'),
    witness = join(control, 'latest.sqlite'),
    encryptionKey = randomBytes(32);
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const options = { database, encryptionKey, clock: () => 1000 };
  return {
    database,
    witness,
    options,
    open: (mode, overrides = {}) =>
      new DurableExecutor({ ...options, rollbackWitness: { mode, path: witness }, ...overrides }),
  };
}
const spec = {
  id: 'task',
  principalId: 'host',
  tenantId: 'tenant',
  grants: [{ tool: 'write', resources: ['ticket-123'] }],
  budget: { maxCalls: 1, maxConcurrent: 1, maxCost: 1, deadline: 2000 },
};

test(
  'restoring a valid pre-write ledger cannot revive revoked credentials or enable a second write',
  posix,
  async t => {
    const f = fixture(t);
    let writes = 0;
    const register = e =>
      e.approveTool(
        'write',
        e.registerTool({
          name: 'write',
          description: 'change ticket',
          maxCost: 1,
          requiresApproval: true,
          resolve: () => ({ tenantId: 'tenant', resourceId: 'ticket-123' }),
          execute: () => ({ value: ++writes, actualCost: 1 }),
        }),
      );
    let e = f.open('create');
    let task;
    try {
      register(e);
      task = e.createTask(spec);
    } finally {
      e.close();
    }
    const backup = readFileSync(f.database);
    e = f.open('resume');
    try {
      register(e);
      const id = e.authenticate(task.token);
      const action = await e.prepare(id, { tool: 'write', args: null });
      assert.equal(
        await e.execute(id, action.id, {
          approvalId: e.approve(action.id, { approverId: 'reviewer', expiresAt: 1500 }),
        }),
        1,
      );
      e.revokeTask(id);
    } finally {
      e.close();
    }
    const current = readFileSync(f.database),
      reference = readFileSync(f.witness);
    assert.equal(reference.includes(Buffer.from(task.token)), false);
    writeFileSync(f.database, backup);
    assert.throws(() => f.open('resume'), { code: 'STORE_WITNESS_UNAVAILABLE' });
    assert.throws(() => new DurableExecutor(f.options), { code: 'STORE_UNAVAILABLE' }); // no unfenced downgrade
    assert.throws(() => f.open('create'), { code: 'STORE_WITNESS_UNAVAILABLE' });
    assert.deepEqual(readFileSync(f.witness), reference);
    writeFileSync(f.database, current);
    e = f.open('resume');
    try {
      assert.throws(() => e.authenticate(task.token), { code: 'UNAUTHENTICATED' });
      assert.equal(e.snapshot(task.taskId).spent, 1);
      assert.equal(writes, 1);
    } finally {
      e.close();
    }
  },
);

test('an absent, stale, substituted or shared witness never bootstraps an existing ledger', posix, t => {
  const a = fixture(t),
    b = fixture(t);
  const active = a.open('create');
  try {
    assert.throws(() => a.open('resume'), { code: 'STORE_WITNESS_UNAVAILABLE' });
  } finally {
    active.close();
  }
  const older = readFileSync(a.witness),
    op = a.open('resume');
  try {
    op.createTask(spec);
  } finally {
    op.close();
  }
  const matching = readFileSync(a.witness);
  b.open('create').close();
  for (const invalid of [older, readFileSync(b.witness)]) {
    writeFileSync(a.witness, invalid);
    assert.throws(() => a.open('resume'), { code: 'STORE_WITNESS_UNAVAILABLE' });
  }
  rmSync(a.witness);
  assert.throws(() => a.open('resume'), { code: 'STORE_WITNESS_UNAVAILABLE' });
  assert.equal(existsSync(a.witness), false);
  const witnessFd = openSync(a.witness, 'wx', 0o600);
  try {
    writeFileSync(witnessFd, matching);
  } finally {
    closeSync(witnessFd);
  }
  linkSync(a.witness, a.witness + '-alias');
  assert.throws(() => a.open('resume'), { code: 'STORE_WITNESS_UNAVAILABLE' });
  assert.throws(() => a.open('resume', { rollbackWitness: { mode: 'resume', path: a.database + '-witness' } }), {
    code: 'STORE_CONFIG_INVALID',
  });
});

for (const phase of ['before', 'after'])
  test(`crash ${phase} commit recovers matching authority and witness`, posix, t => {
    const f = fixture(t),
      e = f.open('create');
    let task;
    try {
      task = e.createTask(spec);
    } finally {
      e.close();
    }
    const entry = new URL('../dist/index.js', import.meta.url).href;
    const program = `import { DurableExecutor } from ${JSON.stringify(entry)};
    import { DatabaseSync } from 'node:sqlite';
    const [database,path,key,phase] = process.argv.slice(1);
    const e = new DurableExecutor({ database, rollbackWitness: { path, mode:'resume' }, encryptionKey:Buffer.from(key,'hex'), clock:()=>1000 });
    const exec=DatabaseSync.prototype.exec;
    DatabaseSync.prototype.exec=function(sql) {
      if (sql === 'COMMIT' && phase === 'before') process.kill(process.pid, 'SIGKILL');
      const value=exec.call(this,sql);
      if (sql === 'COMMIT' && phase === 'after') process.kill(process.pid, 'SIGKILL');
      return value;
    }; e.revokeTask('task');`;
    const child = spawnSync(
      process.execPath,
      ['--input-type=module', '-e', program, f.database, f.witness, f.options.encryptionKey.toString('hex'), phase],
      { timeout: 10_000 },
    );
    assert.equal(child.signal, 'SIGKILL', child.stderr.toString());
    const resumed = f.open('resume');
    try {
      if (phase === 'before') assert.equal(resumed.authenticate(task.token), task.taskId);
      else assert.throws(() => resumed.authenticate(task.token), { code: 'UNAUTHENTICATED' });
    } finally {
      resumed.close();
    }
  });

test('witness enrollment requires supported filesystem custody and two absolute on-disk paths', () => {
  for (const [db, witness] of [
    [':memory:', '/control/latest'],
    ['/state/db', 'latest'],
    ...(process.platform === 'win32' ? [['C:\\state\\db', 'C:\\control\\latest']] : []),
  ]) {
    assert.throws(
      () =>
        new DurableExecutor({
          database: db,
          encryptionKey: randomBytes(32),
          rollbackWitness: { path: witness, mode: 'create' },
        }),
      { code: 'STORE_CONFIG_INVALID' },
    );
  }
});

test('enrollment rejects physically overlapping restore directories and replaceable ancestors', posix, t => {
  const f = fixture(t),
    data = dirname(f.database),
    nested = join(data, 'nested');
  mkdirSync(nested, { mode: 0o700 });
  const alias = join(dirname(data), 'DATA');
  for (const destination of [data, nested, ...(existsSync(alias) ? [alias, join(alias, 'nested')] : [])]) {
    assert.throws(() => f.open('create', { rollbackWitness: { mode: 'create', path: join(destination, 'witness') } }), {
      code: 'STORE_CONFIG_INVALID',
    });
    assert.equal(existsSync(f.database), false);
  }
  const unsafeParent = join(dirname(data), 'shared'),
    privateChild = join(unsafeParent, 'private');
  mkdirSync(unsafeParent);
  chmodSync(unsafeParent, 0o777);
  mkdirSync(privateChild, { mode: 0o700 });
  assert.throws(() => f.open('create', { rollbackWitness: { mode: 'create', path: join(privateChild, 'latest') } }), {
    code: 'STORE_DIRECTORY_UNSAFE',
  });
  assert.equal(existsSync(f.database), false);
});
