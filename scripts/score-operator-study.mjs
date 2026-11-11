// Offline operator study verifier. Documents and signatures stay on the study machine.
import { createHash, createPublicKey, verify } from 'node:crypto';
import { closeSync, constants, fstatSync, openSync, readSync } from 'node:fs';
import { join } from 'node:path';
import { isEntry } from '../examples/providers/replay.mjs';
const { parseEvidenceJson } = await import(
  new URL('./evidence-json.js', import.meta.resolve('@shieldaai/agent-guard-executor'))
);

export const CASES = Object.freeze({
  approve: {
    answer: 'explained-confirmed-change',
    minimum: 1,
    path: ['exact-review-presented', 'review-approved', 'write-dispatched', 'write-committed'],
  },
  lookalike: {
    answer: 'refused-and-identified-mismatch',
    minimum: 1,
    path: ['wrong-target-presented', 'operator-refused'],
  },
  session: {
    answer: 'reauthenticated-and-explained-expiry',
    minimum: 2,
    path: [
      'scoped-evidence-served',
      'session-revoked',
      'old-session-denied',
      'new-session-authenticated',
      'scoped-evidence-served',
    ],
  },
  relationship: {
    answer: 'identified-unknown-and-required-check',
    minimum: 1,
    path: ['unknown-relationship-served'],
  },
  recovery: {
    answer: 'checked-receipt-and-avoided-retry',
    minimum: 3,
    path: ['write-dispatched', 'write-committed', 'response-lost', 'receipt-read', 'execution-reconciled'],
  },
});
const methods = ['standard', 'keyboard-only', 'assistive-technology'];
const unsafeEvents = new Set(['wrong-target-approved', 'write-retried', 'foreign-disclosure', 'foreign-write']);
const digest = bytes => createHash('sha256').update(bytes).digest('hex');
const hash = value => typeof value === 'string' && /^[a-f0-9]{64}$/.test(value);
const alias = value => typeof value === 'string' && /^[A-Za-z0-9_-]{1,48}$/.test(value);
const check = (valid, code) => {
  if (!valid) throw new Error(code);
};
const exact = (object, fields) =>
  check(
    object &&
      typeof object === 'object' &&
      !Array.isArray(object) &&
      Object.keys(object).length === fields.length &&
      fields.every(field => Object.hasOwn(object, field)),
    'INVALID_FIELDS',
  );
const time = value => {
  const ms = Date.parse(value);
  check(typeof value === 'string' && Number.isFinite(ms) && new Date(ms).toISOString() === value, 'INVALID_TIME');
  return ms;
};
const json = (bytes, limit) => {
  try {
    return parseEvidenceJson(bytes, limit);
  } catch {
    throw new Error('INVALID_JSON');
  }
};
function publicKey(raw) {
  check(typeof raw === 'string' && raw.length === 60, 'INVALID_PUBLIC_KEY');
  try {
    const key = createPublicKey({ key: Buffer.from(raw, 'base64'), type: 'spki', format: 'der' });
    check(
      key.asymmetricKeyType === 'ed25519' && key.export({ type: 'spki', format: 'der' }).toString('base64') === raw,
      'INVALID_PUBLIC_KEY',
    );
    return key;
  } catch {
    throw new Error('INVALID_PUBLIC_KEY');
  }
}
function enrollment(bytes) {
  const e = json(bytes, 32 * 1024);
  exact(e, [
    'kind',
    'studyId',
    'buildSha256',
    'deploymentSha256',
    'briefSha256',
    'start',
    'end',
    'facilitatorKey',
    'backendKey',
    'participants',
  ]);
  check(
    e.kind === 'operator-study-enrollment-v1' &&
      alias(e.studyId) &&
      [e.buildSha256, e.deploymentSha256, e.briefSha256].every(hash),
    'INVALID_ENROLLMENT',
  );
  check(time(e.start) < time(e.end) && time(e.end) - time(e.start) <= 31 * 86_400_000, 'INVALID_WINDOW');
  publicKey(e.facilitatorKey);
  publicKey(e.backendKey);
  check(e.facilitatorKey !== e.backendKey, 'SAME_SIGNER');
  check(Array.isArray(e.participants) && e.participants.length >= 5 && e.participants.length <= 40, 'OPERATOR_COUNT');
  for (const p of e.participants) {
    exact(p, ['alias', 'method']);
    check(alias(p.alias) && methods.includes(p.method), 'INVALID_OPERATOR');
  }
  check(new Set(e.participants.map(p => p.alias)).size === e.participants.length, 'DUPLICATE_OPERATOR');
  for (const method of methods.slice(1))
    check(
      e.participants.some(p => p.method === method),
      'MISSING_ACCESS_METHOD',
    );
  return e;
}
const scenarioIds = Object.keys(CASES);
function matrix(rows, e) {
  check(Array.isArray(rows) && rows.length === e.participants.length * scenarioIds.length, 'INCOMPLETE_MATRIX');
  const output = new Map();
  for (const row of rows) {
    check(
      row && e.participants.some(p => p.alias === row.alias) && Object.hasOwn(CASES, row.scenario),
      'UNENROLLED_ATTEMPT',
    );
    const key = row.alias + '/' + row.scenario;
    check(!output.has(key), 'DUPLICATE_ATTEMPT');
    output.set(key, row);
  }
  return output;
}
export function blankWorksheet(bytes, role) {
  const e = enrollment(bytes);
  check(['facilitator', 'backend'].includes(role), 'INVALID_ROLE');
  const rows = e.participants.flatMap(p =>
    scenarioIds.map(scenario =>
      role === 'facilitator'
        ? {
            alias: p.alias,
            scenario,
            runRef: null,
            method: null,
            assistance: null,
            answer: null,
            unsafeDecision: null,
            disclosure: null,
            criticalBlocker: null,
          }
        : { alias: p.alias, scenario, receiptSha256: null },
    ),
  );
  return {
    kind: 'operator-study-' + role + '-v1',
    enrollmentSha256: digest(bytes),
    ...(role === 'facilitator' ? { witnessedIndependentRepresentativeHumans: null } : {}),
    rows,
  };
}
function signed(bytes, sig, key, kind, pin, extra) {
  check(sig.length === 64 && verify(null, bytes, publicKey(key), sig), 'INVALID_SIGNATURE');
  const v = json(bytes, 256 * 1024);
  exact(v, ['kind', 'enrollmentSha256', 'rows', ...extra]);
  check(v.kind === 'operator-study-' + kind + '-v1' && v.enrollmentSha256 === pin, 'EVIDENCE_BINDING');
  return v;
}
function checkReceipt(r, row, pin, e, now) {
  exact(r, ['kind', 'enrollmentSha256', 'alias', 'scenario', 'runRef', 'capturedAt', 'complete', 'events']);
  check(
    r.kind === 'operator-study-receipt-v1' &&
      r.enrollmentSha256 === pin &&
      r.alias === row.alias &&
      r.scenario === row.scenario &&
      hash(r.runRef) &&
      r.runRef === row.runRef &&
      r.complete === true,
    'RECEIPT_BINDING',
  );
  const captured = time(r.capturedAt);
  check(captured >= time(e.start) && captured <= time(e.end) && captured <= now, 'RECEIPT_TIME');
  const c = CASES[row.scenario];
  check(
    Array.isArray(r.events) && r.events.length >= c.minimum && r.events.length <= 32,
    'INSUFFICIENT_BACKEND_EVIDENCE',
  );
  for (const ev of r.events) {
    exact(ev, ['type', 'ref']);
    check(typeof ev.type === 'string' && hash(ev.ref), 'INVALID_EVENT');
  }
  const events = r.events.map(ev => ev.type),
    first = r.events[0].ref;
  // Per-case event streams are complete projections of the enrolled audit window.
  // Session renewal must change credential identity. A write and its receipt must retain operation identity.
  const badBinding = r.events.some((ev, i) =>
    row.scenario === 'session' && i >= 3 ? ev.ref === first || ev.ref !== r.events[3].ref : ev.ref !== first,
  );
  const expectedPrefix = events.slice(0, c.minimum).every((ev, i) => ev === c.path[i]);
  check(expectedPrefix, 'INSUFFICIENT_BACKEND_EVIDENCE');
  const unsafe =
    events.some(ev => unsafeEvents.has(ev)) ||
    events.filter(ev => ev === 'write-dispatched').length > 1 ||
    events.filter(ev => ev === 'write-committed').length > 1 ||
    (row.scenario === 'lookalike' && events.includes('review-approved'));
  const prefix = events.every((ev, i) => ev === c.path[i]);
  const safeDecline = row.scenario === 'approve' && events.join(',') === 'exact-review-presented,operator-refused';
  const complete = prefix && events.length === c.path.length && !badBinding;
  return { unsafe, badEvidence: badBinding || (!unsafe && !prefix && !safeDecline), complete };
}
export function scoreStudy({
  enrollmentBytes,
  expectedDigest,
  facilitatorBytes,
  facilitatorSignature,
  backendBytes,
  backendSignature,
  readReceipt,
  now = Date.now(),
}) {
  const pin = digest(enrollmentBytes);
  check(hash(expectedDigest) && pin === expectedDigest, 'ENROLLMENT_CHANGED');
  const e = enrollment(enrollmentBytes);
  const facilitator = signed(facilitatorBytes, facilitatorSignature, e.facilitatorKey, 'facilitator', pin, [
    'witnessedIndependentRepresentativeHumans',
  ]);
  check(facilitator.witnessedIndependentRepresentativeHumans === true, 'HUMAN_WITNESS_REQUIRED');
  const observations = matrix(facilitator.rows, e);
  const manifests = matrix(signed(backendBytes, backendSignature, e.backendKey, 'backend', pin, []).rows, e);
  const failures = new Set(),
    runRefs = new Set(),
    receiptRefs = new Set(),
    eventRefs = new Set();
  const metric = () => ({ successful: 0, planned: 0 });
  const byScenario = Object.fromEntries(scenarioIds.map(s => [s, metric()]));
  const byMethod = Object.fromEntries([...new Set(e.participants.map(p => p.method))].map(m => [m, metric()]));
  const overall = metric();
  for (const [key, row] of observations) {
    exact(row, [
      'alias',
      'scenario',
      'runRef',
      'method',
      'assistance',
      'answer',
      'unsafeDecision',
      'disclosure',
      'criticalBlocker',
    ]);
    const method = e.participants.find(p => p.alias === row.alias).method;
    check(
      row.method === method &&
        ['none', 'prompted', 'abandoned'].includes(row.assistance) &&
        [CASES[row.scenario].answer, 'incomplete', 'unsafe'].includes(row.answer) &&
        [row.unsafeDecision, row.disclosure, row.criticalBlocker].every(v => typeof v === 'boolean'),
      'INCOMPLETE_OBSERVATION',
    );
    check(hash(row.runRef) && !runRefs.has(row.runRef), 'REUSED_OR_MISSING_RUN');
    runRefs.add(row.runRef);
    const manifest = manifests.get(key);
    exact(manifest, ['alias', 'scenario', 'receiptSha256']);
    check(hash(manifest.receiptSha256) && !receiptRefs.has(manifest.receiptSha256), 'REUSED_OR_MISSING_RECEIPT');
    receiptRefs.add(manifest.receiptSha256);
    const raw = readReceipt(manifest.receiptSha256);
    check(
      raw instanceof Uint8Array && raw.length <= 16 * 1024 && digest(raw) === manifest.receiptSha256,
      'RECEIPT_CHANGED',
    );
    const receipt = json(raw, 16 * 1024);
    const observed = checkReceipt(receipt, row, pin, e, now);
    for (const ref of new Set(receipt.events.map(ev => ev.ref))) {
      check(!eventRefs.has(ref), 'REUSED_EVENT_IDENTITY');
      eventRefs.add(ref);
    }
    if (observed.unsafe || row.unsafeDecision || row.disclosure || row.answer === 'unsafe')
      failures.add('UNSAFE_OR_DISCLOSED');
    if (row.criticalBlocker) failures.add('CRITICAL_ACCESSIBILITY_BLOCKER');
    if (observed.badEvidence || (row.answer === CASES[row.scenario].answer && !observed.complete))
      failures.add('UNSUPPORTED_OBSERVATION');
    const success =
      row.assistance === 'none' &&
      row.answer === CASES[row.scenario].answer &&
      observed.complete &&
      !observed.unsafe &&
      !row.unsafeDecision &&
      !row.disclosure &&
      !row.criticalBlocker;
    if (!success && ['lookalike', 'recovery'].includes(row.scenario)) failures.add('CRITICAL_TASK_FAILED');
    for (const m of [overall, byScenario[row.scenario], byMethod[method]]) {
      m.planned++;
      if (success) m.successful++;
    }
  }
  const missedThresholds = [];
  if (overall.successful * 100 < overall.planned * 90) missedThresholds.push('PILOT_COMPLETION_FLOOR');
  const pilot = !failures.size && !missedThresholds.length;
  const groupsMeetFloor = [...Object.values(byMethod), ...Object.values(byScenario)].every(
    m => m.successful * 100 >= m.planned * 80,
  );
  if (overall.successful * 100 < overall.planned * 96) missedThresholds.push('STRETCH_COMPLETION_FLOOR');
  if (!groupsMeetFloor) missedThresholds.push('STRETCH_GROUP_FLOOR');
  const stretch = !failures.size && !missedThresholds.length;
  return {
    status: stretch ? 'stretch-met' : pilot ? 'pilot-only' : 'failed',
    enrollmentSha256: pin,
    participants: e.participants.length,
    pilot,
    stretch,
    failures: [...failures].sort(),
    missedThresholds,
    overall,
    byScenario,
    byMethod,
  };
}
function read(path, maximum) {
  check(typeof constants.O_NONBLOCK === 'number' && typeof constants.O_NOFOLLOW === 'number', 'UNSUPPORTED_FILE_OPEN');
  const fd = openSync(path, constants.O_RDONLY | constants.O_NONBLOCK | constants.O_NOFOLLOW);
  try {
    const stat = fstatSync(fd);
    check(stat.isFile() && stat.size <= maximum, 'INPUT_LIMIT');
    const buf = Buffer.alloc(maximum + 1);
    let size = 0;
    while (size < buf.length) {
      const n = readSync(fd, buf, size, buf.length - size, null);
      if (!n) break;
      size += n;
    }
    check(size <= maximum, 'INPUT_LIMIT');
    return buf.subarray(0, size);
  } finally {
    closeSync(fd);
  }
}
export function cli(args, now = Date.now()) {
  if (args[0] === 'enroll' && args.length === 3) {
    const bytes = read(args[1], 32768),
      e = enrollment(bytes);
    check(now < time(e.start), 'ENROLL_BEFORE_STUDY');
    check(digest(read(args[2], 65536)) === e.briefSha256, 'BRIEF_CHANGED');
    return { status: 'unmeasured', enrollmentSha256: digest(bytes) };
  }
  if (args[0] === 'worksheet' && args.length === 3) return blankWorksheet(read(args[1], 32768), args[2]);
  check(args[0] === 'score' && args.length === 8, 'INVALID_COMMAND');
  const [, file, pin, facilitator, fsig, backend, bsig, dir] = args;
  return scoreStudy({
    enrollmentBytes: read(file, 32768),
    expectedDigest: pin,
    facilitatorBytes: read(facilitator, 262144),
    facilitatorSignature: read(fsig, 64),
    backendBytes: read(backend, 262144),
    backendSignature: read(bsig, 64),
    now,
    readReceipt: h => read(join(dir, h + '.json'), 16384),
  });
}
if (isEntry(import.meta)) {
  try {
    const result = cli(process.argv.slice(2));
    console.log(JSON.stringify(result, null, 2));
    if (result.stretch === false) process.exitCode = 1;
  } catch (e) {
    const reason = /^[A-Z_]+$/.test(e.message) ? e.message : 'INVALID_OR_UNREADABLE_INPUT';
    console.error(JSON.stringify({ status: 'unverified', reason }));
    process.exitCode = 2;
  }
}
