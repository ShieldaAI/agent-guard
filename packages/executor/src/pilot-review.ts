import { createHash } from 'node:crypto';
import { types } from 'node:util';
import { isIP } from 'node:net';
import { type Json } from '@shieldaai/agent-guard';
import { digestJson, immutableJson } from '@shieldaai/agent-guard/internal';
import { BuildProvenancePolicy, type BuildArtifactRule, type BuildAttestationEnvelope } from './build-provenance.js';
import { parseEvidenceJson } from './evidence-json.js';
import { boundedBase64, enrolledSigningKey, verifyEnvelopeBytes } from './signed-evidence.js';

type PilotMode = 'company-pilot' | 'rehearsal';
interface PilotSigner { readonly subject: string; readonly publicKeyPem: string }

export interface PilotReviewPolicy {
  readonly version: 1;
  readonly mode: PilotMode;
  readonly companyId: string;
  readonly deploymentId: string;
  readonly boundarySha256: string;
  readonly runId: string;
  readonly notBefore: number;
  readonly expiresAt: number;
  readonly candidate: BuildArtifactRule;
  readonly observer: PilotSigner;
  readonly reviewer: PilotSigner;
  readonly minLoadSamples: number;
  readonly maxLatencyP95Ms: number;
}

type Section = 'access' | 'recovery' | 'load';
export interface PilotReviewBundle {
  readonly version: 1;
  readonly boundary: string;
  readonly buildAttestation: BuildAttestationEnvelope;
  readonly observations: BuildAttestationEnvelope;
  readonly review: BuildAttestationEnvelope;
  readonly evidence: Readonly<Record<Section, string>>;
}

export interface PilotReviewResult {
  readonly version: 1;
  readonly status: 'verified';
  readonly expiresAt: number;
  readonly boundarySha256: string;
  readonly mode: PilotMode;
  readonly policySha256: string;
  readonly candidateSha256: string;
  readonly buildStatementSha256: string;
  readonly observationSha256: string;
  readonly reviewSha256: string;
  readonly loadSamples: number;
  readonly latencyP95Ms: number;
}

type Row = Readonly<Record<string, Json>>;
const hash = (bytes: Uint8Array) => createHash('sha256').update(bytes).digest('hex');
const OBSERVATION_TYPE = 'application/vnd.agent-guard.pilot-observations.v1+json';
const REVIEW_TYPE = 'application/vnd.agent-guard.pilot-review.v1+json';
const SECTION_BYTES = 128 * 1024;
const MAX_WINDOW_MS = 31 * 86_400_000;
const byteLength = Object.getOwnPropertyDescriptor(Object.getPrototypeOf(Uint8Array.prototype), 'byteLength')!.get!;
const backingBuffer = Object.getOwnPropertyDescriptor(Object.getPrototypeOf(Uint8Array.prototype), 'buffer')!.get!;

function invalid(): never { throw new Error('Pilot review verification failed'); }
function fields(value: Json | undefined, names: readonly string[]): Row {
  if (!value || typeof value !== 'object' || Array.isArray(value) ||
      Object.keys(value).length !== names.length || names.some((key) => !Object.hasOwn(value, key))) invalid();
  return value as Row;
}
function integer(value: Json | undefined, min: number, max = Number.MAX_SAFE_INTEGER): number {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < min || value > max) invalid();
  return value;
}
function sha(value: Json | undefined): string {
  if (typeof value !== 'string' || !/^[0-9a-f]{64}$/u.test(value)) invalid();
  return value;
}
function identifier(value: Json | undefined): string {
  if (typeof value !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,127}$/u.test(value)) invalid();
  return value;
}
function signer(value: Json | undefined) {
  const entry = fields(value, ['subject', 'publicKeyPem']);
  return { subject: identifier(entry.subject), ...enrolledSigningKey(entry.publicKeyPem) };
}

function httpsEndpoint(value: Json | undefined, originOnly: boolean): string {
  if (typeof value !== 'string' || value.length > 2048 || !/^https:\/\//u.test(value) ||
      /[\s\\?#]/u.test(value)) invalid();
  const url = new URL(value);
  const host = url.hostname;
  const ip = isIP(host.startsWith('[') ? host.slice(1, -1) : host);
  if (!ip && (host.length > 253 || host.split('.').some((part) =>
    !/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/u.test(part)))) invalid();
  if (/\*|%2a/iu.test(url.pathname)) invalid();
  if (url.protocol !== 'https:' || url.username || url.password ||
      (originOnly && url.origin !== value) || (url.href !== value && url.origin !== value)) invalid();
  return value;
}

function checkBoundary(encoded: Json | undefined, policy: Row, candidate: BuildArtifactRule): string {
  const bytes = boundedBase64(encoded, 16 * 1024);
  const digest = hash(bytes);
  if (digest !== policy.boundarySha256) invalid();
  const boundary = fields(parseEvidenceJson(bytes, 16 * 1024), [
    'version', 'companyId', 'deploymentId', 'tenantId', 'candidateSha256', 'oidcIssuer', 'oidcAudience',
    'httpsOrigin', 'awsRoleArn', 'expectedBucketOwner', 'awsAction', 'awsResourceArn', 'protectedTool', 'excludedSurfaces',
  ]);
  if (boundary.version !== 1 || boundary.companyId !== policy.companyId || boundary.deploymentId !== policy.deploymentId ||
      boundary.tenantId !== candidate.tenantId || boundary.candidateSha256 !== candidate.sha256) invalid();
  httpsEndpoint(boundary.oidcIssuer, false);
  httpsEndpoint(boundary.httpsOrigin, true);
  identifier(boundary.oidcAudience);
  identifier(boundary.protectedTool);
  const role = boundary.awsRoleArn;
  const resource = boundary.awsResourceArn;
  if (typeof role !== 'string' || role.length > 1024 || typeof resource !== 'string' || resource.length > 2048 ||
      boundary.awsAction !== 's3:GetBucketLocation' || /[\s*?\\\x00-\x1f\x7f]/u.test(resource)) invalid();
  const roleMatch = /^arn:aws:iam::([0-9]{12}):role\/(?:[a-zA-Z0-9_+=,.@-]+\/)*[a-zA-Z0-9_+=,.@-]+$/u.exec(role);
  const bucket = /^arn:aws:s3:::([a-z0-9][a-z0-9.-]{1,61}[a-z0-9])$/u.exec(resource)?.[1];
  if (!roleMatch || roleMatch[1] !== boundary.expectedBucketOwner || !bucket ||
      bucket.includes('..') || /^\d+\.\d+\.\d+\.\d+$/u.test(bucket)) invalid();
  if (!Array.isArray(boundary.excludedSurfaces) || boundary.excludedSurfaces.length > 32) invalid();
  const excluded = boundary.excludedSurfaces.map(identifier);
  if (new Set(excluded).size !== excluded.length || excluded.includes(boundary.protectedTool as string)) invalid();
  return digest;
}

const positive = new Set(['oidc-read', 'rotated-tls-read', 'rotated-key-read', 'aws-read']);
const negative = new Set(['foreign-tenant-read', 'revoked-session-read', 'retired-tls-read', 'retired-key-read', 'aws-write']);
function checkAccess(value: Json | undefined): void {
  if (!Array.isArray(value) || value.length !== positive.size + negative.size) invalid();
  const seen = new Set<string>();
  for (const item of value) {
    const probe = fields(item, ['name', 'outcome', 'backendReads', 'backendWrites']);
    const name = identifier(probe.name);
    if (seen.has(name) || (!positive.has(name) && !negative.has(name))) invalid();
    seen.add(name);
    const allowed = positive.has(name);
    if (probe.outcome !== (allowed ? 'allowed' : 'denied') ||
        probe.backendReads !== (allowed ? 1 : 0) || probe.backendWrites !== 0) invalid();
  }
}

function checkRecovery(section: Row): void {
  const before = fields(section.before, ['logicalStateSha256', 'records']);
  const restored = fields(section.restored, ['logicalStateSha256', 'records']);
  if (sha(before.logicalStateSha256) !== restored.logicalStateSha256 ||
      integer(before.records, 1) !== restored.records) invalid();
  const incident = fields(section.incident, ['initialStatus', 'finalStatus', 'receiptSha256', 'effectsBefore', 'effectsAfter']);
  sha(incident.receiptSha256);
  if (incident.initialStatus !== 'UNKNOWN' || incident.finalStatus !== 'SUCCEEDED' ||
      incident.effectsBefore !== 1 || incident.effectsAfter !== 1) invalid();
}

function checkLoad(section: Row, minSamples: number, limit: number, runStarted: number) {
  const values = section.latenciesMs;
  if (!Array.isArray(values) || values.length < minSamples || values.length > 2048 ||
      section.totalAttempts !== values.length || section.failedAttempts !== 0) invalid();
  const elapsed = integer(section.collectedAt, runStarted) - runStarted;
  const ordered = values.map((value) => integer(value, 0, Math.min(elapsed, 86_400_000))).sort((a, b) => a - b);
  const p95 = ordered[Math.ceil(ordered.length * 0.95) - 1]!;
  if (p95 > limit) invalid();
  return { loadSamples: ordered.length, latencyP95Ms: p95 };
}

/** Read-only evidence verification. Provision policy and the verifier clock outside the evidence collection path. */
export function verifyPilotReview(policy: PilotReviewPolicy, candidateBytes: Uint8Array, bundle: PilotReviewBundle,
  expectedMode: PilotMode = 'company-pilot'): PilotReviewResult {
  try {
    const p = fields(immutableJson(policy, 8, 256, 32 * 1024), [
      'version', 'mode', 'companyId', 'deploymentId', 'runId', 'notBefore', 'expiresAt', 'boundarySha256',
      'candidate', 'observer', 'reviewer', 'minLoadSamples', 'maxLatencyP95Ms',
    ]);
    if (p.version !== 1 || (expectedMode !== 'company-pilot' && expectedMode !== 'rehearsal') || p.mode !== expectedMode) invalid();
    identifier(p.companyId);
    identifier(p.deploymentId);
    sha(p.runId);
    const start = integer(p.notBefore, 0);
    const expiry = integer(p.expiresAt, start + 1);
    if (expiry - start > MAX_WINDOW_MS) invalid();
    const minSamples = integer(p.minLoadSamples, 20, 2048);
    const latencyLimit = integer(p.maxLatencyP95Ms, 1, 86_400_000);
    const policySha256 = digestJson(p);
    const observer = signer(p.observer);
    const reviewer = signer(p.reviewer);
    if (observer.subject === reviewer.subject || observer.signerSha256 === reviewer.signerSha256) invalid();

    const candidate = p.candidate as unknown as BuildArtifactRule;
    const builds = new BuildProvenancePolicy({ artifacts: [candidate] });
    if (!types.isUint8Array(candidateBytes) || types.isSharedArrayBuffer(Reflect.apply(backingBuffer, candidateBytes, [])) ||
        Reflect.apply(byteLength, candidateBytes, []) > 64 * 1024 * 1024) invalid();
    const candidateSha256 = hash(candidateBytes);
    const b = fields(immutableJson(bundle, 8, 128, 1024 * 1024), ['version', 'boundary', 'buildAttestation', 'observations', 'review', 'evidence']);
    if (b.version !== 1) invalid();
    const boundarySha256 = checkBoundary(b.boundary, p, candidate);
    const built = builds.verify({ tenantId: candidate.tenantId, path: candidate.path, sha256: candidateSha256,
      attestation: b.buildAttestation as unknown as BuildAttestationEnvelope });
    if (built.signerSha256 === observer.signerSha256 || built.signerSha256 === reviewer.signerSha256) invalid();

    const observations = verifyEnvelopeBytes(b.observations, OBSERVATION_TYPE, observer, 16 * 1024);
    const observationSha256 = hash(observations);
    const obs = fields(parseEvidenceJson(observations, 16 * 1024), [
      'policySha256', 'mode', 'runId', 'candidateSha256', 'buildStatementSha256', 'startedAt', 'finishedAt', 'evidence',
    ]);
    if (obs.policySha256 !== policySha256 || obs.mode !== p.mode || obs.runId !== p.runId ||
        obs.candidateSha256 !== candidateSha256 || obs.buildStatementSha256 !== built.statementSha256) invalid();
    const started = integer(obs.startedAt, start, expiry - 1);
    const finished = integer(obs.finishedAt, started, expiry - 1);
    const review = verifyEnvelopeBytes(b.review, REVIEW_TYPE, reviewer, 16 * 1024);
    const verdict = fields(parseEvidenceJson(review, 16 * 1024), [
      'policySha256', 'mode', 'runId', 'observationSha256', 'decision', 'reviewedAt', 'openExceptions',
    ]);
    if (verdict.policySha256 !== policySha256 || verdict.mode !== p.mode || verdict.runId !== p.runId ||
        verdict.observationSha256 !== observationSha256 || verdict.decision !== 'approve' ||
        !Array.isArray(verdict.openExceptions) || verdict.openExceptions.length) invalid();
    const reviewed = integer(verdict.reviewedAt, finished, expiry - 1);
    const names = ['access', 'recovery', 'load'] as const;
    const refs = fields(obs.evidence, names);
    const attachments = fields(b.evidence, names);
    const section = (name: Section, keys: string[]): Row => {
      const bytes = boundedBase64(attachments[name], SECTION_BYTES);
      if (refs[name] !== hash(bytes)) invalid();
      const row = fields(parseEvidenceJson(bytes, SECTION_BYTES), ['kind', 'policySha256', 'collectedAt', 'sourceReport', ...keys]);
      if (row.kind !== name || row.policySha256 !== policySha256) invalid();
      integer(row.collectedAt, started, finished);
      // Preserve the original redacted evidence for review separately from its normalized measurements.
      boundedBase64(row.sourceReport, 64 * 1024);
      return row;
    };
    checkAccess(section('access', ['probes']).probes);
    checkRecovery(section('recovery', ['before', 'restored', 'incident']));
    const load = checkLoad(section('load', ['totalAttempts', 'failedAttempts', 'latenciesMs']), minSamples, latencyLimit, started);
    integer(Date.now(), reviewed, expiry - 1);
    return Object.freeze({ version: 1, status: 'verified', mode: p.mode, policySha256, candidateSha256, boundarySha256, expiresAt: expiry,
      buildStatementSha256: built.statementSha256, observationSha256, reviewSha256: hash(review), ...load });
  } catch {
    return invalid();
  }
}
