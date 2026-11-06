import nodeTest from 'node:test';
import assert from 'node:assert/strict';
import { setup } from './helpers.mjs';
import { openMaintenance, openRuntime } from '../runtime.mjs';
const test = (name, fn) => nodeTest(name, { skip: process.platform === 'win32' ? 'The witnessed single-owner deployment requires POSIX.' : false }, fn);

test('recovery status requires both native mirrors and verified history enrollment', t => {
  const fixture = setup(t);
  assert.equal(fixture.runtime.recovery.mode, 'not-enrolled');
  fixture.close();
  const stores = openMaintenance(fixture.config);
  try { stores.guard.enableRecoveryMirror(); } finally { stores.close(); }
  const runtime = fixture.reopen();
  assert.equal(runtime.recovery.executorMirror, true);
  assert.equal(runtime.recovery.backendMirror, false);
  assert.equal(runtime.recovery.historyMirror, false);
  assert.equal(runtime.recovery.mode, 'not-enrolled');
  assert.equal(Object.isFrozen(runtime.recovery), true);
  fixture.close();
  const both = openMaintenance(fixture.config);
  try { both.backend.enableRecoveryMirror(); } finally { both.close(); }
  const nativeOnly = fixture.reopen().recovery;
  assert.equal(nativeOnly.executorMirror && nativeOnly.backendMirror, true);
  assert.equal(nativeOnly.historyMirror, false);
  assert.equal(nativeOnly.mode, 'not-enrolled');
});

test('an unbound history mirror cannot produce a verified recovery status', t => {
  const fixture = setup(t, { mirror: true });
  assert.equal(fixture.runtime.recovery.mode, 'current-state-mirror');
  assert.deepEqual(Object.keys(fixture.runtime.recovery).sort(), ['backendMirror', 'executorMirror', 'historyMirror', 'mode', 'verifiedAt']);
  fixture.runtime.backend.transaction(state => { state.ticketService.history.mirrorEnrollment.inode = '0'; });
  fixture.close();
  assert.throws(() => openRuntime(fixture.config), { code: 'HISTORY_MIRROR_NOT_ENROLLED' });
});
