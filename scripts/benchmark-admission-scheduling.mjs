// Private benchmark evidence only. No authority, HTTP metadata or scheduler mutation.
import assert from 'node:assert/strict';

export function workerSchedulingMode(value = 'default') {
  assert.ok(value === 'default' || value === 'linux-background', 'ADMISSION_WORKER_SCHEDULING_INVALID');
  return value;
}
const keys = (value, expected) => {
  assert.ok(value !== null && typeof value === 'object' && !Array.isArray(value), 'SCHEDULING_EVIDENCE_INVALID');
  assert.deepEqual(Object.keys(value).sort(), [...expected].sort(), 'SCHEDULING_EVIDENCE_INVALID');
};
const nice = value => Number.isInteger(value) && value >= -20 && value <= 19;
const tid = value => Number.isInteger(value) && value > 0 && value <= 0x7fffffff;

export function validateSchedulingReading(value, requested) {
  workerSchedulingMode(requested);
  if (requested === 'default') {
    keys(value, ['mode', 'verified']);
    assert.equal(value.mode, 'default'); assert.equal(value.verified, false);
    return;
  }
  keys(value, ['mode', 'verified', 'workerTid', 'beforeNice', 'afterNice', 'currentNice',
    'ownerTid', 'ownerBeforeNice', 'ownerCurrentNice']);
  assert.equal(value.mode, 'linux-background'); assert.equal(value.verified, true);
  assert.ok(tid(value.workerTid) && tid(value.ownerTid) && value.workerTid !== value.ownerTid);
  for (const name of ['beforeNice', 'afterNice', 'currentNice', 'ownerBeforeNice', 'ownerCurrentNice']) assert.ok(nice(value[name]));
  assert.equal(value.afterNice, Math.min(19, value.beforeNice + 10));
  assert.equal(value.currentNice, value.afterNice);
  assert.equal(value.ownerCurrentNice, value.ownerBeforeNice);
}

export function schedulingEvidenceValid(phases, requested) {
  try {
    workerSchedulingMode(requested);
    assert.equal(phases.length, 4);
    for (const phase of phases) {
      const value = phase.workerScheduling;
      keys(value, ['requested', 'before', 'after']); assert.equal(value.requested, requested);
      if (phase.mode === 'baseline') {
        // The unchanged baseline owns no observer; never create one for evidence.
        assert.equal(value.before, null); assert.equal(value.after, null);
      } else {
        assert.equal(phase.mode, 'polling');
        validateSchedulingReading(value.before, requested); validateSchedulingReading(value.after, requested);
        assert.deepEqual(value.after, value.before, 'SCHEDULING_CHANGED');
      }
    }
    return true;
  } catch { return false; }
}
