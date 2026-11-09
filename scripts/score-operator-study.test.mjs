import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import { constants, mkdtempSync, mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { blankWorksheet, CASES, cli, scoreStudy } from './score-operator-study.mjs';

const hash = b => createHash('sha256').update(b).digest('hex');
const bytes = v => Buffer.from(JSON.stringify(v));
const signer = () => generateKeyPairSync('ed25519');
const pub = k => k.publicKey.export({ format: 'der', type: 'spki' }).toString('base64');
// Generated cryptographic/interaction fixtures only. Never accepted as real observations.
function round({ changeEnrollment = () => {}, change = () => {} } = {}) {
  const facilitator = signer(),
    backend = signer();
  const enrolled = {
    kind: 'operator-study-enrollment-v1',
    studyId: 'test-fixture',
    buildSha256: hash('build'),
    deploymentSha256: hash('deploy'),
    briefSha256: hash('brief'),
    start: '2025-01-01T00:00:00.000Z',
    end: '2025-01-02T00:00:00.000Z',
    facilitatorKey: pub(facilitator),
    backendKey: pub(backend),
    participants: ['keyboard-only', 'assistive-technology', 'standard', 'standard', 'standard'].map((method, i) => ({
      alias: 'fake-' + i,
      method,
    })),
  };
  changeEnrollment(enrolled);
  const enrollmentBytes = bytes(enrolled),
    pin = hash(enrollmentBytes);
  const obs = blankWorksheet(enrollmentBytes, 'facilitator'),
    manifest = blankWorksheet(enrollmentBytes, 'backend');
  obs.witnessedIndependentRepresentativeHumans = true;
  const facts = obs.rows.map((row, i) => {
    const c = CASES[row.scenario],
      ref = hash('event' + i),
      runRef = hash('run' + i);
    Object.assign(row, {
      runRef,
      method: enrolled.participants.find(p => p.alias === row.alias).method,
      assistance: 'none',
      answer: c.answer,
      unsafeDecision: false,
      disclosure: false,
      criticalBlocker: false,
    });
    return {
      kind: 'operator-study-receipt-v1',
      enrollmentSha256: pin,
      alias: row.alias,
      scenario: row.scenario,
      runRef,
      capturedAt: '2025-01-01T04:00:00.000Z',
      complete: true,
      events: c.path.map((type, j) => ({
        type,
        ref: row.scenario === 'session' && j >= 3 ? hash('new' + i) : ref,
      })),
    };
  });
  const receipts = new Map();
  // Mutate observations or recorded events before signing to exercise independent content checks.
  change({ obs, manifest, facts });
  for (const row of manifest.rows) {
    const receipt = facts.find(r => r.alias === row.alias && r.scenario === row.scenario);
    if (!receipt) continue;
    const raw = bytes(receipt);
    row.receiptSha256 = hash(raw);
    receipts.set(row.receiptSha256, raw);
  }
  const facilitatorBytes = bytes(obs),
    backendBytes = bytes(manifest);
  const input = {
    enrollmentBytes,
    expectedDigest: pin,
    facilitatorBytes,
    backendBytes,
    facilitatorSignature: sign(null, facilitatorBytes, facilitator.privateKey),
    backendSignature: sign(null, backendBytes, backend.privateKey),
    readReceipt: h => receipts.get(h),
    now: Date.parse('2025-01-03T00:00:00Z'),
  };
  return { input, receipts };
}
const result = opts => scoreStudy(round(opts).input);

test('full witnessed matrix and signed same-attempt evidence pass; report exposes only grouped counts', () => {
  const r = result();
  assert.equal(r.status, 'stretch-met');
  assert.deepEqual(r.overall, { successful: 25, planned: 25 });
  assert.deepEqual(r.byMethod['assistive-technology'], { successful: 5, planned: 5 });
  assert.deepEqual(r.byScenario.recovery, { successful: 5, planned: 5 });
  assert.ok(!JSON.stringify(r).includes('fake-'));
});
test('96 percent stretch distinguishes pilot and failed utility; assistance consumes a planned attempt', () => {
  const score = n =>
    result({
      change: ({ obs }) => {
        for (const i of [10, 15, 20]) {
          if (n-- <= 0) break;
          obs.rows[i].assistance = 'prompted';
        }
      },
    });
  assert.equal(score(1).status, 'stretch-met');
  assert.equal(score(2).status, 'pilot-only');
  assert.equal(score(3).status, 'failed');
});
test('a high aggregate cannot mask inaccessible tasks for a small access-method group', () => {
  const r = result({
    changeEnrollment(e) {
      for (let i = 0; i < 15; i++) e.participants.push({ alias: 'extra-' + i, method: 'standard' });
    },
    change({ obs }) {
      obs.rows[5].assistance = 'prompted';
      obs.rows[8].answer = 'incomplete';
    },
  });
  assert.deepEqual(r.overall, { successful: 98, planned: 100 });
  assert.equal(r.status, 'pilot-only');
  assert.ok(r.missedThresholds.includes('STRETCH_GROUP_FLOOR'));
});
test('every safety failure, even under a high aggregate score, bars both gates', () => {
  for (const change of [
    ({ obs }) => (obs.rows[1].answer = 'incomplete'),
    ({ obs }) => (obs.rows[4].assistance = 'prompted'),
    ({ obs }) => (obs.rows[8].criticalBlocker = true),
    ({ obs }) => (obs.rows[3].disclosure = true),
    ({ obs }) => (obs.rows[0].unsafeDecision = true),
    ({ facts }) => facts[4].events.push({ ...facts[4].events[0] }),
    ({ facts }) => facts[1].events.splice(1, 1, { type: 'wrong-target-approved', ref: facts[1].events[0].ref }),
    ({ facts }) => facts[4].events.pop(),
    ({ facts }) => (facts[4].events.at(-1).ref = hash('wrong-operation')),
    ({ facts }) => (facts[2].events[3].ref = facts[2].events[0].ref),
  ])
    assert.equal(result({ change }).status, 'failed');
});
test('an incomplete or substituted enrollment, observation matrix, or audit window cannot pass', () => {
  for (const changeEnrollment of [
    e => e.participants.pop(),
    e => (e.participants[0].method = 'standard'),
    e => (e.participants[1].method = 'standard'),
    e => (e.participants[3].alias = e.participants[2].alias),
    e => (e.backendKey = e.facilitatorKey),
  ])
    assert.throws(() => result({ changeEnrollment }));
  for (const change of [
    ({ obs }) => obs.rows.pop(),
    ({ obs }) => (obs.rows[2] = obs.rows[1]),
    ({ obs }) => (obs.rows[0].alias = 'unknown'),
    ({ manifest }) => manifest.rows.pop(),
    ({ manifest }) => (manifest.rows[4] = manifest.rows[3]),
    ({ obs }) => (obs.witnessedIndependentRepresentativeHumans = false),
    ({ obs }) => (obs.rows[0].method = 'standard'),
    ({ facts }) => (facts[0].complete = false),
    ({ facts }) => (facts[1].events = []),
    ({ facts }) => facts[4].events.splice(2),
    ({ facts }) => (facts[2].capturedAt = '2025-01-05T00:00:00.000Z'),
    ({ facts }) => (facts[3].runRef = facts[0].runRef),
    ({ facts }) => (facts[3].events[0].ref = facts[0].events[0].ref),
  ])
    assert.throws(() => result({ change }));
});
test('detached signatures and source bytes bind the exact enrollment, roles and per-attempt receipts', () => {
  const { input } = round();
  for (const mutation of [
    { expectedDigest: hash('different') },
    { backendSignature: input.facilitatorSignature },
    { facilitatorBytes: Buffer.concat([input.facilitatorBytes, Buffer.from('\n')]) },
    { readReceipt: () => undefined },
    { readReceipt: () => Buffer.from('{}') },
    { now: 0 },
  ]) {
    assert.throws(() => scoreStudy({ ...input, ...mutation }));
  }
});
test('offline command reads signed receipt files; a frozen enrollment on its own remains unmeasured', t => {
  if (typeof constants.O_NONBLOCK !== 'number' || typeof constants.O_NOFOLLOW !== 'number') {
    assert.throws(() => cli(['enroll', 'unopened', 'unopened']), /UNSUPPORTED_FILE_OPEN/);
    return;
  }
  const dir = mkdtempSync(join(tmpdir(), 'operator-study-fixture-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const { input, receipts } = round();
  const store = (name, b) => {
    const file = join(dir, name);
    writeFileSync(file, b);
    return file;
  };
  const enrollment = store('enrollment', input.enrollmentBytes),
    brief = store('brief', 'brief');
  assert.equal(cli(['enroll', enrollment, brief], 0).status, 'unmeasured');
  assert.throws(() => cli(['enroll', enrollment, brief], input.now), /ENROLL_BEFORE_STUDY/);
  assert.throws(() => cli(['enroll', enrollment, store('wrong', 'changed')], 0), /BRIEF_CHANGED/);
  const blank = cli(['worksheet', enrollment, 'facilitator']);
  assert.equal(blank.rows.length, 25);
  assert.ok(blank.rows.every(row => row.answer === null && row.runRef === null));
  const rdir = join(dir, 'receipts');
  mkdirSync(rdir);
  for (const [h, raw] of receipts) writeFileSync(join(rdir, h + '.json'), raw);
  const args = [
    'score',
    enrollment,
    input.expectedDigest,
    store('f', input.facilitatorBytes),
    store('fs', input.facilitatorSignature),
    store('b', input.backendBytes),
    store('bs', input.backendSignature),
    rdir,
  ];
  assert.equal(cli(args).stretch, true);
  rmSync(join(rdir, [...receipts.keys()][0] + '.json'));
  assert.throws(() => cli(args));
});
