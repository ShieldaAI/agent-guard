import { strict as assert } from 'node:assert';
import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import test from 'node:test';
import { BuildProvenancePolicy } from '../dist/build-provenance.js';

const mediaType = 'application/vnd.in-toto+json';
const digest = bytes => createHash('sha256').update(bytes).digest('hex');
const pair = generateKeyPairSync('ed25519');
const otherPair = generateKeyPairSync('ed25519');
const pem = key => key.export({ type: 'spki', format: 'pem' });
const keyId = key => digest(key.export({ type: 'spki', format: 'der' }));
const failure = {
  name: 'ExecutorError',
  code: 'BUILD_PROVENANCE_INVALID',
  message: 'BUILD_PROVENANCE_INVALID: Build provenance validation failed',
};

function rule() {
  return {
    tenantId: 'tenant-a',
    path: 'dist/tool.js',
    subjectName: 'packages/dist/tool.js',
    sha256: digest('tool bytes'),
    sourceDigest: { algorithm: 'sha256', value: digest('source') },
    sourceUri: 'git+https://source.example.test/repo',
    buildType: 'https://example.test/build/v1',
    builderId: 'https://builder.example.test/ci',
    signerPublicKeyPem: pem(pair.publicKey),
  };
}

function statement(r) {
  return {
    _type: 'https://in-toto.io/Statement/v1',
    subject: [{ name: r.subjectName, digest: { sha256: r.sha256 } }],
    predicateType: 'https://slsa.dev/provenance/v1',
    predicate: {
      buildDefinition: {
        buildType: r.buildType,
        externalParameters: {},
        resolvedDependencies: [{ uri: r.sourceUri, digest: { [r.sourceDigest.algorithm]: r.sourceDigest.value } }],
      },
      runDetails: { builder: { id: r.builderId } },
    },
  };
}

function envelope(bytes, signingPair = pair, options = {}) {
  const media = Buffer.from(mediaType, 'ascii');
  const signed = options.raw
    ? bytes
    : Buffer.concat([
        Buffer.from('DSSEv1'),
        Buffer.from(' ' + media.byteLength + ' '),
        media,
        Buffer.from(' ' + (options.length ?? bytes.byteLength) + ' '),
        bytes,
      ]);
  return {
    payloadType: mediaType,
    payload: bytes.toString('base64'),
    signatures: [
      {
        keyid: keyId(signingPair.publicKey),
        sig: sign(null, signed, signingPair.privateKey).toString('base64'),
      },
    ],
  };
}

const encode = data => Buffer.from(JSON.stringify(data));
const policy = (...rules) => new BuildProvenancePolicy({ artifacts: rules });
const request = (r, attestation) => ({ tenantId: r.tenantId, path: r.path, sha256: r.sha256, attestation });

test('DSSE admission hashes the original UTF-8 statement and returns only enrolled digest evidence', () => {
  const r = rule(),
    verifier = policy(r),
    s = statement(r);
  s.predicate.runDetails.builder.version = { compiler: 'v2' };
  s.predicate.runDetails.metadata = { invocationId: '雪 { "x": [3] }', startedOn: '2026-01-01T00:00:00Z' };
  const bytes = Buffer.from(JSON.stringify(s, null, 2) + '\n');
  const evidence = verifier.verify(request(r, envelope(bytes)));
  assert.deepEqual(evidence, {
    signerSha256: keyId(pair.publicKey),
    statementSha256: digest(bytes),
    policySha256: verifier.digest,
  });
  assert.ok(Object.isFrozen(evidence));
  assert.notEqual(bytes.length, bytes.toString().length);
  for (const opts of [{ raw: true }, { length: bytes.toString().length }]) {
    assert.throws(() => verifier.verify(request(r, envelope(bytes, pair, opts))), failure);
  }
});

test('policy hashing is stable across rule order and PEM line endings and binds every trust pin', () => {
  const r = rule(),
    second = { ...r, tenantId: 'tenant-b' };
  const baseline = policy(r, second).digest;
  assert.equal(
    policy(second, { ...r, signerPublicKeyPem: r.signerPublicKeyPem.replaceAll('\n', '\r\n') }).digest,
    baseline,
  );
  for (const change of [
    { tenantId: 'tenant-c' },
    { path: 'another/file' },
    { sha256: digest('different') },
    { sourceDigest: { algorithm: 'sha1', value: 'a'.repeat(40) } },
    { subjectName: 'unrelated' },
    { sourceUri: 'urn:evidence:second' },
    { buildType: 'urn:build:v2' },
    { builderId: 'urn:builder:b' },
    { signerPublicKeyPem: pem(otherPair.publicKey) },
  ]) {
    assert.notEqual(policy({ ...r, ...change }, second).digest, baseline);
  }
  assert.throws(() => policy(r, { ...r, path: r.path.toUpperCase() }), failure);
});

test('caller mutations cannot replace trust after enrollment; literal SHA-1 source descriptors are supported', () => {
  const r = rule();
  r.sourceDigest = { algorithm: 'sha1', value: 'a'.repeat(40) };
  const s = statement(r);
  s.predicate.buildDefinition.externalParameters = null;
  s.predicate.buildDefinition.internalParameters = {};
  const req = request(r, envelope(encode(s)));
  const v = policy(r);
  r.sourceDigest.value = 'b'.repeat(40);
  r.signerPublicKeyPem = pem(otherPair.publicKey);
  assert.equal(v.verify(req).signerSha256, keyId(pair.publicKey));
  assert.throws(() => v.verify(request(r, envelope(encode(statement(r)), otherPair))), failure);
  for (const overrides of [{ tenantId: 'other' }, { path: 'dist/Tool.js' }, { sha256: digest('swapped') }]) {
    assert.throws(() => v.verify({ ...req, ...overrides }), failure);
  }
});

test('genuinely signed claims cannot change an enrolled subject, builder, build type, or resolved source', () => {
  const r = rule(),
    v = policy(r);
  const mutations = {
    statementType: s => (s._type = 'https://in-toto.io/Statement/v0.1'),
    predicateType: s => (s.predicateType = 'https://slsa.dev/provenance/v0.2'),
    subjectName: s => (s.subject[0].name += '-other'),
    subjectHash: s => (s.subject[0].digest.sha256 = digest('wrong')),
    extraSubject: s => s.subject.push(structuredClone(s.subject[0])),
    emptySubject: s => (s.subject = []),
    extraSubjectDigest: s => (s.subject[0].digest.md5 = 'bad'),
    builder: s => (s.predicate.runDetails.builder.id += '/other'),
    type: s => (s.predicate.buildDefinition.buildType += '/other'),
    source: s => (s.predicate.buildDefinition.resolvedDependencies[0].uri += '#other'),
    sourceHash: s => (s.predicate.buildDefinition.resolvedDependencies[0].digest.sha256 = digest('wrong')),
    sourceAlgorithm: s =>
      (s.predicate.buildDefinition.resolvedDependencies[0].digest = { gitCommit: r.sourceDigest.value }),
    extraSource: s =>
      s.predicate.buildDefinition.resolvedDependencies.push(
        structuredClone(s.predicate.buildDefinition.resolvedDependencies[0]),
      ),
    sourceAlias: s => (s.predicate.buildDefinition.resolvedDependencies[0].downloadLocation = 'https://other.test'),
    externalParams: s => (s.predicate.buildDefinition.externalParameters = { command: 'untrusted' }),
    internalParams: s => (s.predicate.buildDefinition.internalParameters = { build: true }),
    badMetadata: s => (s.predicate.runDetails.metadata = { unauthorized: 'data' }),
    badVersion: s => (s.predicate.runDetails.builder.version = { compiler: 17 }),
  };
  for (const [reason, mutate] of Object.entries(mutations)) {
    const s = statement(r);
    mutate(s);
    assert.throws(() => v.verify(request(r, envelope(encode(s)))), failure, reason);
  }
});

test('rejects unsigned, malformed, and substituted envelope values without exposing supplied strings', () => {
  const r = rule(),
    v = policy(r),
    bytes = encode(statement(r));
  const good = envelope(bytes),
    spoofed = envelope(bytes, otherPair);
  spoofed.signatures[0].keyid = keyId(pair.publicKey);
  const sig = good.signatures[0];
  for (const item of [
    spoofed,
    { ...good, payloadType: 'application/json' },
    { ...good, payload: encode({ bad: true }).toString('base64') },
    { ...good, signatures: [] },
    { ...good, signatures: [sig, sig] },
    { ...good, signatures: [{ ...sig, keyid: sig.keyid.toUpperCase() }] },
    { ...good, signatures: [{ ...sig, key: pem(otherPair.publicKey) }] },
    { ...good, private: 'SECRET_CANARY' },
    { ...good, payload: good.payload + ' ' },
    { ...good, signatures: [{ ...sig, sig: sig.sig.replace(/=+$/, '') }] },
    { ...good, signatures: [{ ...sig, sig: Buffer.alloc(63).toString('base64') }] },
    { ...good, signatures: [{ ...sig, sig: Buffer.alloc(65).toString('base64') }] },
  ])
    assert.throws(() => v.verify(request(r, item)), failure);
});

test('rejects signed malformed JSON, escaped duplicate object keys, invalid UTF-8, and oversized statements', () => {
  const r = rule(),
    v = policy(r),
    json = JSON.stringify(statement(r));
  const texts = [
    '',
    '\ufeff' + json,
    json.replace('"subject":', '"subject":[],"subject":'),
    json.replace('"predicateType":', '"predic\\u0061teType":"other","predicateType":'),
    json.replace('"id":', '"id":"untrusted","id":'),
    '['.repeat(50) + '0' + ']'.repeat(50),
    '[' + Array(8193).fill('0').join(',') + ']',
    json + ' '.repeat(128 * 1024),
  ];
  for (const bytes of [...texts.map(t => Buffer.from(t)), Buffer.from([0xc0, 0x80])]) {
    assert.throws(() => v.verify(request(r, envelope(bytes))), failure);
  }
});

test('requires bounded public-only Ed25519 SPKI keys, safe paths, stable URIs and exact policy schema', () => {
  const r = rule();
  const wrongKey = generateKeyPairSync('x25519');
  const der = pair.publicKey.export({ type: 'spki', format: 'der' });
  const trailing = Buffer.concat([der, Buffer.from([0])]).toString('base64');
  for (const change of [
    { signerPublicKeyPem: pem(wrongKey.publicKey) },
    { signerPublicKeyPem: pair.privateKey.export({ type: 'pkcs8', format: 'pem' }) },
    { signerPublicKeyPem: r.signerPublicKeyPem + r.signerPublicKeyPem },
    { signerPublicKeyPem: '-----BEGIN PUBLIC KEY-----\n' + trailing + '\n-----END PUBLIC KEY-----\n' },
    { signerPublicKeyPem: 'x'.repeat(2049) },
    { path: '../new' },
    { path: 'root/new.' },
    { path: 'data/AUx.txt' },
    { path: '/abs' },
    { path: '.agent-guard-provenance.json' },
    { path: 'a\\b' },
    { sourceUri: 'https://user:pwd@source.example' },
    { buildType: ' invalid ' },
    { builderId: '.relative' },
    { sha256: r.sha256.toUpperCase() },
    { sourceDigest: { algorithm: 'sha1', value: r.sha256 } },
    { sourceDigest: { algorithm: 'md5', value: r.sha256 } },
    { tenantId: 'a\nb' },
    { extra: true },
  ])
    assert.throws(() => policy({ ...r, ...change }), failure);
  assert.throws(() => policy(), failure);
  assert.throws(() => policy(...Array.from({ length: 129 }, (_, i) => ({ ...r, tenantId: 't' + i }))), failure);
});

test('rejects accessor input without invoking caller code', () => {
  const r = rule(),
    v = policy(r);
  let reads = 0;
  const hostile = {
    get keyid() {
      reads++;
      return keyId(pair.publicKey);
    },
    sig: 'ABC',
  };
  assert.throws(
    () =>
      policy({
        ...r,
        get sha256() {
          reads++;
          return r.sha256;
        },
      }),
    failure,
  );
  const e = envelope(encode(statement(r)));
  assert.throws(() => v.verify(request(r, { ...e, signatures: [hostile] })), failure);
  assert.equal(reads, 0);
});
