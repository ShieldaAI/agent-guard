// Disposable rehearsal signer. Neither private role key leaves this function.
import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import { readFileSync } from 'node:fs';

const hash = (value) => createHash('sha256').update(value).digest('hex');
const encode = (value) => Buffer.from(JSON.stringify(value, null, 2) + '\n');
const canonical = (value) => {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return '[' + value.map(canonical).join(',') + ']';
  return '{' + Object.keys(value).sort().map((name) => JSON.stringify(name) + ':' + canonical(value[name])).join(',') + '}';
};
const pem = (publicKey) => publicKey.export({ type: 'spki', format: 'pem' });
function envelope(payloadType, bytes, keys) {
  const prefix = Buffer.from(['DSSEv1', Buffer.byteLength(payloadType), payloadType, bytes.length, ''].join(' '));
  const signature = sign(null, Buffer.concat([prefix, bytes]), keys.privateKey);
  return { payloadType, payload: bytes.toString('base64'), signatures: [{
    keyid: hash(keys.publicKey.export({ type: 'spki', format: 'der' })), sig: signature.toString('base64'),
  }] };
}

export function createPilotReviewFixture(options = {}) {
  const now = Date.now();
  const { rule, attestation } = JSON.parse(readFileSync(new URL('packed-build-attestation.json', import.meta.url)));
  const candidateBytes = Buffer.from('fixture');
  const observer = generateKeyPairSync('ed25519');
  const reviewer = options.sharedKey ? observer : generateKeyPairSync('ed25519');
  const boundary = {
    version: 1, companyId: 'test-company', tenantId: rule.tenantId, deploymentId: 'test-deployment',
    candidateSha256: rule.sha256, oidcIssuer: 'https://id.example.test/issuer', oidcAudience: 'pilot-client',
    httpsOrigin: 'https://pilot.example.test', awsRoleArn: 'arn:aws:iam::123456789012:role/pilot',
    expectedBucketOwner: '123456789012', awsAction: 's3:GetBucketLocation', awsResourceArn: 'arn:aws:s3:::pilot-bucket',
    protectedTool: 'read-report', excludedSurfaces: ['container-launch'],
  };
  options.boundary?.(boundary);
  const boundaryBytes = encode(boundary);
  const policy = {
    version: 1, mode: 'rehearsal', companyId: 'test-company', deploymentId: 'test-deployment',
    boundarySha256: hash(boundaryBytes), runId: hash('synthetic-run'), notBefore: now - 60000, expiresAt: now + 60000, candidate: rule,
    observer: { subject: 'observer', publicKeyPem: pem(observer.publicKey) },
    reviewer: { subject: 'reviewer', publicKeyPem: pem(reviewer.publicKey) },
    minLoadSamples: 20, maxLatencyP95Ms: 95,
  };
  options.policy?.(policy);
  const policySha256 = hash(canonical(policy));
  const section = (kind) => ({
    kind, policySha256, collectedAt: now - 2000,
    sourceReport: Buffer.from('private-' + kind + '-canary').toString('base64'),
  });
  const allowed = ['oidc-read', 'rotated-tls-read', 'rotated-key-read', 'aws-read'];
  const denied = ['foreign-tenant-read', 'revoked-session-read', 'retired-tls-read', 'retired-key-read', 'aws-write'];
  const sections = {
    access: { ...section('access'), probes: [...allowed, ...denied].map((name) => ({
      name, outcome: allowed.includes(name) ? 'allowed' : 'denied', backendReads: allowed.includes(name) ? 1 : 0, backendWrites: 0,
    })) },
    recovery: { ...section('recovery'), before: { logicalStateSha256: hash('state'), records: 3 },
      restored: { logicalStateSha256: hash('state'), records: 3 },
      incident: { initialStatus: 'UNKNOWN', finalStatus: 'SUCCEEDED', receiptSha256: hash('receipt'), effectsBefore: 1, effectsAfter: 1 } },
    load: { ...section('load'), totalAttempts: 100, failedAttempts: 0, latenciesMs: Array.from({ length: 100 }, (_, i) => i + 1) },
  };
  options.sections?.(sections);
  const sectionBytes = Object.fromEntries(Object.entries(sections).map(([name, value]) => [name, encode(value)]));
  options.sectionBytes?.(sectionBytes);
  const common = { mode: policy.mode, runId: policy.runId, policySha256 };
  const obs = { ...common, candidateSha256: hash(candidateBytes), buildStatementSha256: hash(Buffer.from(attestation.payload, 'base64')),
    startedAt: now - 4000, finishedAt: now - 1000,
    evidence: Object.fromEntries(Object.entries(sectionBytes).map(([name, bytes]) => [name, hash(bytes)])) };
  options.observations?.(obs);
  const ob = options.observationBytes?.(encode(obs)) ?? encode(obs);
  const verdict = { ...common, observationSha256: hash(ob), decision: 'approve', reviewedAt: now - 500, openExceptions: [] };
  options.review?.(verdict);
  const bundle = {
    version: 1, boundary: boundaryBytes.toString('base64'), buildAttestation: attestation, observations: envelope('application/vnd.agent-guard.pilot-observations.v1+json', ob, observer),
    review: envelope('application/vnd.agent-guard.pilot-review.v1+json', encode(verdict), reviewer),
    evidence: Object.fromEntries(Object.entries(sectionBytes).map(([name, bytes]) => [name, bytes.toString('base64')])),
  };
  return { policy, candidateBytes, bundle };
}
