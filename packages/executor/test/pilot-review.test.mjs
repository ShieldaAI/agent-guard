import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { verifyPilotReview } from '../dist/entry-pilot.js';
import { createPilotReviewFixture as fixture } from './fixtures/pilot-review.mjs';

const check = ({ policy, candidateBytes, bundle }) => verifyPilotReview(policy, candidateBytes, bundle, 'rehearsal');
const refuse = f => assert.throws(() => check(f), { message: 'Pilot review verification failed' });
const sha = value => createHash('sha256').update(value).digest('hex');
const decode = base64 => Buffer.from(base64, 'base64');

test('joins a byte-pinned build, deployment boundary, observer evidence and independent verdict', () => {
  const f = fixture();
  const result = check(f);
  assert(Object.isFrozen(result));
  assert.equal(result.status, 'verified');
  assert.equal(result.mode, 'rehearsal');
  assert.equal(result.expiresAt, f.policy.expiresAt);
  assert.equal(result.boundarySha256, sha(decode(f.bundle.boundary)));
  assert.equal(result.candidateSha256, sha(f.candidateBytes));
  assert.equal(result.observationSha256, sha(decode(f.bundle.observations.payload)));
  assert.equal(result.reviewSha256, sha(decode(f.bundle.review.payload)));
  assert.equal(result.loadSamples, 100);
  assert.equal(result.latencyP95Ms, 95);
  const output = JSON.stringify(result);
  for (const secret of [
    f.policy.companyId,
    f.policy.candidate.tenantId,
    f.policy.candidate.sourceUri,
    f.policy.observer.publicKeyPem,
    'canary',
    'pilot-bucket',
    'id.example.test',
    f.bundle.evidence.access,
  ]) {
    assert.equal(output.includes(secret), false);
  }
});

test('after signing, no run, tenant, candidate, build, boundary, key, evidence, mode or threshold may be substituted', () => {
  const original = fixture();
  const other = fixture();
  for (const change of [
    f => {
      f.policy.mode = 'company-pilot';
    },
    f => {
      f.policy.runId = '0'.repeat(64);
    },
    f => {
      f.policy.companyId += '2';
    },
    f => {
      f.policy.deploymentId += '2';
    },
    f => {
      f.policy.candidate.tenantId += '2';
    },
    f => {
      f.policy.maxLatencyP95Ms++;
    },
    f => {
      f.policy.observer = other.policy.observer;
    },
    f => {
      f.bundle.review = other.bundle.review;
    },
    f => {
      f.bundle.observations = other.bundle.observations;
    },
    f => {
      f.bundle.boundary = 'YWJj';
    },
    f => {
      f.bundle.evidence.access = other.bundle.evidence.access;
    },
    f => {
      f.candidateBytes[0]++;
    },
    f => {
      f.bundle.buildAttestation.signatures[0].sig = 'AA==';
    },
    f => {
      f.bundle.review.payloadType = f.bundle.observations.payloadType;
    },
    f => {
      f.bundle.review.signatures[0].sig = f.bundle.observations.signatures[0].sig;
    },
    f => {
      f.bundle.observations.signatures[0].keyid = f.bundle.review.signatures[0].keyid;
    },
  ]) {
    const f = structuredClone(original);
    change(f);
    refuse(f);
  }
});

test('the library requires explicit rehearsal intent and binds the requested mode before returning a receipt', () => {
  const rehearsal = fixture(),
    companyProfile = fixture({
      policy(p) {
        p.mode = 'company-pilot';
      },
    });
  const args = f => [f.policy, f.candidateBytes, f.bundle];
  assert.throws(() => verifyPilotReview(...args(rehearsal)));
  assert.throws(() => verifyPilotReview(...args(companyProfile), 'rehearsal'));
  assert.throws(() => verifyPilotReview(...args(rehearsal), 'any'));
  assert.equal(verifyPilotReview(...args(rehearsal), 'rehearsal').mode, 'rehearsal');
  assert.equal(verifyPilotReview(...args(companyProfile)).mode, 'company-pilot');
  const shared = new Uint8Array(new SharedArrayBuffer(rehearsal.candidateBytes.length));
  shared.set(rehearsal.candidateBytes);
  assert.throws(() => verifyPilotReview(rehearsal.policy, shared, rehearsal.bundle, 'rehearsal'));
});

test('signed fractional counts cannot round into passing backend controls', () => {
  const withNumber = (field, original, replacement) =>
    fixture({
      sectionBytes(bytes) {
        bytes.access = Buffer.from(
          bytes.access.toString().replace('"' + field + '": ' + original, '"' + field + '": ' + replacement),
        );
      },
    });
  for (const expression of ['1e-999', '-1e-999']) refuse(withNumber('backendWrites', 0, expression));
  for (const expression of ['0.99999999999999999999', '1.00000000000000000001'])
    refuse(withNumber('backendReads', 1, expression));
  assert.equal(check(withNumber('backendWrites', 0, '0.00e-300')).status, 'verified');
  assert.equal(check(withNumber('backendReads', 1, '0.010e2')).status, 'verified');
});

test('one role cannot vouch for another and only an explicit unqualified approval counts', () => {
  refuse(fixture({ sharedKey: true }));
  for (const policy of [
    p => {
      p.reviewer.subject = p.observer.subject;
    },
    p => {
      p.observer.publicKeyPem = p.candidate.signerPublicKeyPem;
    },
    p => {
      p.reviewer.publicKeyPem = p.candidate.signerPublicKeyPem;
    },
    p => {
      p.runId = 'short';
    },
    p => {
      p.minLoadSamples = 1;
    },
  ])
    refuse(fixture({ policy }));
  for (const review of [
    r => {
      r.decision = 'reject';
    },
    r => {
      r.openExceptions = ['unresolved'];
    },
    r => {
      r.observationSha256 = '0'.repeat(64);
    },
    r => {
      r.mode = 'company-pilot';
    },
  ])
    refuse(fixture({ review }));
});

test('requires an enrolled HTTPS/OIDC deployment and exact same-account S3 metadata target', () => {
  for (const boundary of [
    b => {
      b.tenantId = 'other';
    },
    b => {
      b.candidateSha256 = '1'.repeat(64);
    },
    b => {
      b.oidcIssuer = 'http://id.example.test';
    },
    b => {
      b.httpsOrigin += '/path';
    },
    b => {
      b.httpsOrigin = 'https://*.example.test';
    },
    b => {
      b.httpsOrigin = 'https://.';
    },
    b => {
      b.oidcIssuer = 'https://id.example.test/%2a';
    },
    b => {
      b.oidcIssuer = 'https://*';
    },
    b => {
      b.oidcIssuer = 'https://credential@id.example.test';
    },
    b => {
      b.oidcAudience = '*';
    },
    b => {
      b.expectedBucketOwner = '000000000000';
    },
    b => {
      b.awsRoleArn = 'arn:aws:iam::123456789012:root';
    },
    b => {
      b.awsAction = 's3:GetObject';
    },
    b => {
      b.awsResourceArn += '/customer-object';
    },
    b => {
      b.awsResourceArn = 'arn:aws:s3:::*';
    },
    b => {
      b.excludedSurfaces = [b.protectedTool];
    },
  ])
    refuse(fixture({ boundary }));
  const f = fixture();
  const replacement = fixture({
    boundary: b => {
      b.httpsOrigin = 'https://other.example.test';
    },
  });
  f.bundle.boundary = replacement.bundle.boundary;
  f.policy.boundarySha256 = replacement.policy.boundarySha256;
  refuse(f);
});

test('valid signatures cannot relax probe controls, exact recovery, reconciliation or sample thresholds', () => {
  for (const sections of [
    s => {
      s.access.probes.pop();
    },
    s => {
      s.access.probes[1] = s.access.probes[0];
    },
    s => {
      s.access.probes[0].outcome = 'denied';
    },
    s => {
      s.access.probes[4].backendReads = 1;
    },
    s => {
      s.access.probes.at(-1).backendWrites = 1;
    },
    s => {
      s.recovery.restored.records--;
    },
    s => {
      s.recovery.restored.logicalStateSha256 = '0'.repeat(64);
    },
    s => {
      s.recovery.incident.effectsAfter = 2;
    },
    s => {
      s.recovery.incident.initialStatus = 'FAILED';
    },
    s => {
      s.load.latenciesMs = s.load.latenciesMs.slice(0, 19);
      s.load.totalAttempts = 19;
    },
    s => {
      s.load.failedAttempts = 1;
    },
    s => {
      s.load.totalAttempts++;
    },
    s => {
      s.load.latenciesMs[s.load.latenciesMs.length - 1] = 86_400_000;
    }, // Tail outlier exceeds the whole run, even though p95 still passes.
    s => {
      s.load.latenciesMs[94]++;
    },
    s => {
      s.load.latenciesMs[0] = -1;
    },
    s => {
      s.load.sourceReport = '';
    },
    s => {
      s.access.policySha256 = '0'.repeat(64);
    },
  ])
    refuse(fixture({ sections }));
  for (const observations of [
    o => {
      o.evidence.recovery = o.evidence.load;
    },
    o => {
      o.buildStatementSha256 = o.candidateSha256;
    },
    o => {
      o.candidateSha256 = '0'.repeat(64);
    },
    o => {
      o.runId = '1'.repeat(64);
    },
  ])
    refuse(fixture({ observations }));
});

test('enforces the host window, review ordering, observation collection bounds and exclusive expiry', t => {
  const base = Date.now();
  t.mock.method(Date, 'now', () => base);
  const f = fixture();
  check(f);
  for (const options of [
    {
      policy: p => {
        p.notBefore = base - 2000;
      },
    },
    {
      policy: p => {
        p.expiresAt = p.notBefore + 32 * 86400000;
      },
    },
    {
      observations: o => {
        o.finishedAt = o.startedAt - 1;
      },
    },
    {
      review: r => {
        r.reviewedAt = base + 1;
      },
    },
    {
      review: r => {
        r.reviewedAt = base - 3000;
      },
    },
    {
      sections: s => {
        s.access.collectedAt = base;
      },
    },
  ])
    refuse(fixture(options));
  Date.now.mock.mockImplementation(() => f.policy.expiresAt);
  refuse(f);
});

test('fails closed on ambiguous signed JSON, oversized evidence, sparse arrays and accessor-backed input', () => {
  refuse(
    fixture({
      observationBytes: bytes => Buffer.from(bytes.toString().replace('"mode":', '"mode":"early","m\\u006fde":')),
    }),
  );
  refuse(
    fixture({
      sectionBytes: parts => {
        parts.access = Buffer.from([0xff]);
      },
    }),
  );
  refuse(
    fixture({
      sections: s => {
        s.load.sourceReport = Buffer.alloc(65537).toString('base64');
      },
    }),
  );
  const f = fixture();
  let called = false;
  Object.defineProperty(f.bundle.evidence, 'load', {
    enumerable: true,
    get() {
      called = true;
      throw Error('private');
    },
  });
  refuse(f);
  assert.equal(called, false);
  const oversized = fixture();
  oversized.bundle.evidence.load = 'A'.repeat(1024 * 1024);
  refuse(oversized);
  const sparse = fixture();
  sparse.bundle.review.signatures = new Array(1);
  refuse(sparse);
});
