import test from 'node:test';
import assert from 'node:assert/strict';
import { workerSchedulingMode, validateSchedulingReading, schedulingEvidenceValid } from './benchmark-admission-scheduling.mjs';
import { main, runAdmissionPhase } from './benchmark-admission.mjs';

const reading = (beforeNice = 0, ownerBeforeNice = 0) => ({ mode: 'linux-background', verified: true,
  workerTid: 12, beforeNice, afterNice: Math.min(19, beforeNice + 5), currentNice: Math.min(19, beforeNice + 5),
  ownerTid: 10, ownerBeforeNice, ownerCurrentNice: ownerBeforeNice });
const phases = requested => ['baseline', 'polling', 'polling', 'baseline'].map(mode => {
  const value = requested === 'default' ? { mode: 'default', verified: false } : reading();
  return { mode, workerScheduling: { requested, before: mode === 'polling' ? { ...value } : null,
    after: mode === 'polling' ? { ...value } : null } };
});

test('worker scheduling selection is explicit and invalid modes fail before fixture or output creation', async () => {
  assert.equal(workerSchedulingMode(), 'default'); assert.equal(workerSchedulingMode('linux-background'), 'linux-background');
  for (const value of [null, false, 0, '', 'DEFAULT', 'linux-background\n', 'nice', {}, ['default']]) {
    assert.throws(() => workerSchedulingMode(value));
    await assert.rejects(runAdmissionPhase({ mode: 'baseline', samples: 1, warmup: 1, workerScheduling: value }));
  }
  await assert.rejects(main(['--worker-scheduling', 'invalid', '--output', '/not-created/scheduling.json']));
  if (process.platform !== 'linux')
    await assert.rejects(runAdmissionPhase({ mode: 'polling', samples: 1, warmup: 1, workerScheduling: 'linux-background' }),
      { message: 'ADMISSION_WORKER_SCHEDULING_INVALID' });
});

test('private scheduling evidence verifies lower-only clamp and unchanged owner with bounded exact fields', () => {
  validateSchedulingReading({ mode: 'default', verified: false }, 'default');
  for (const before of [-20, -11, 0, 8, 9, 10, 14, 19]) validateSchedulingReading(reading(before), 'linux-background');
  for (const mutate of [x => { x.workerTid = 0; }, x => { x.workerTid = x.ownerTid; }, x => { x.ownerTid = 2 ** 31; },
    x => { x.beforeNice = -21; }, x => { x.afterNice = 20; }, x => { x.currentNice = 4; },
    x => { x.ownerCurrentNice = 1; }, x => { x.verified = false; }, x => { x.mode = 'default'; },
    x => { x.privatePath = 'not retained'; }, x => { delete x.ownerBeforeNice; }]) {
    const value = reading(); mutate(value); assert.throws(() => validateSchedulingReading(value, 'linux-background'));
  }
  assert.throws(() => validateSchedulingReading({ mode: 'default', verified: true }, 'default'));
  assert.throws(() => validateSchedulingReading(reading(), 'default'));
});

test('rejected ten-level readings cannot qualify the restored five-level background policy', () => {
  // When targets differ, the rejected policy fails even with consistent readback and owner.
  // At an initial nice >=14 both policies clamp to19; exact source binding distinguishes those runs.
  for (const beforeNice of [-20, 0, 8, 9, 10, 13]) {
    const old = { ...reading(beforeNice), afterNice: Math.min(19, beforeNice + 10), currentNice: Math.min(19, beforeNice + 10) };
    assert.throws(() => validateSchedulingReading(old, 'linux-background'));
    const previous = phases('linux-background');
    for (const phase of previous.filter(value => value.mode === 'polling')) {
      phase.workerScheduling.before = { ...old }; phase.workerScheduling.after = { ...old };
    }
    assert.equal(schedulingEvidenceValid(previous, 'linux-background'), false);
  }
});

test('baseline creates no observer and polling evidence must bind the same live worker before and after', () => {
  for (const requested of ['default', 'linux-background']) assert.equal(schedulingEvidenceValid(phases(requested), requested), true);
  assert.equal(schedulingEvidenceValid(phases('default'), 'linux-background'), false);
  assert.equal(schedulingEvidenceValid([], 'default'), false);
  for (const change of [x => { x[1].workerScheduling.after = null; },
    x => { x[1].workerScheduling.after.workerTid++; }, x => { x[1].workerScheduling.after.ownerTid++; },
    x => { x[1].workerScheduling.after = reading(5); }, x => { x[0].workerScheduling.before = reading(); },
    x => { x[0].workerScheduling.requested = 'default'; }, x => { x[2].workerScheduling.after.ownerCurrentNice++; }]) {
    const value = phases('linux-background'); change(value); assert.equal(schedulingEvidenceValid(value, 'linux-background'), false);
  }
});

test('background benchmark verifies the actual Linux worker policy and refuses unsupported hosts without fallback', async () => {
  const options = { mode: 'polling', samples: 2, warmup: 1, tasks: 2, grants: 2,
    pollIntervalMs: 10, workerScheduling: 'linux-background' };
  if (process.platform !== 'linux') {
    await assert.rejects(runAdmissionPhase(options), { message: 'ADMISSION_WORKER_SCHEDULING_INVALID' });
    return;
  }
  const result = await runAdmissionPhase(options);
  assert.equal(result.error, undefined); assert.equal(result.successfulEffects, 3); assert.equal(result.finalCalls, 3);
  validateSchedulingReading(result.workerScheduling.before, 'linux-background');
  assert.deepEqual(result.workerScheduling.after, result.workerScheduling.before);
  assert.equal(result.polling.failed, 0); assert.ok(result.polling.completed >= 1);
  assert.ok(Object.values(result.cleanup).every(value => value === true));
});
