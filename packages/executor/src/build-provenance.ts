import { enrolledSigningKey, verifyEnvelopeBytes } from './signed-evidence.js';
import { parseEvidenceJson } from './evidence-json.js';
import { createHash, type KeyObject } from 'node:crypto';
import { type Json } from '@shieldaai/agent-guard';
import { digestJson, immutableJson } from '@shieldaai/agent-guard/internal';

export interface BuildArtifactRule {
  readonly tenantId: string;
  readonly path: string;
  readonly sha256: string;
  readonly subjectName: string;
  readonly builderId: string;
  readonly buildType: string;
  readonly sourceUri: string;
  readonly sourceDigest: { readonly algorithm: 'sha1' | 'sha256'; readonly value: string };
  readonly signerPublicKeyPem: string;
}

export interface BuildArtifactPolicy {
  readonly artifacts: readonly BuildArtifactRule[];
}

export interface BuildAttestationEnvelope {
  readonly payloadType: string;
  readonly payload: string;
  readonly signatures: readonly { readonly keyid: string; readonly sig: string }[];
}

export interface BuildProvenanceEvidence {
  readonly policySha256: string;
  readonly statementSha256: string;
  readonly signerSha256: string;
}

type RecordValue = Readonly<Record<string, Json>>;
type Enrolled = Omit<BuildArtifactRule, 'signerPublicKeyPem'> & { readonly signerSha256: string };
const MEDIA_TYPE = 'application/vnd.in-toto+json';
const MAX_STATEMENT_BYTES = 128 * 1024;
const hash = (value: Uint8Array): string => createHash('sha256').update(value).digest('hex');

function invalid(): never {
  throw new Error('Build provenance validation failed');
}

function record(value: Json | undefined): RecordValue {
  if (!value || typeof value !== 'object' || Array.isArray(value)) invalid();
  return value as RecordValue;
}

function fields(value: Json | undefined, required: readonly string[], optional: readonly string[] = []): RecordValue {
  const object = record(value);
  if (
    required.some(key => !Object.hasOwn(object, key)) ||
    Object.keys(object).some(key => !required.includes(key) && !optional.includes(key))
  )
    invalid();
  return object;
}

function text(value: Json | undefined, maximum = 2048): string {
  if (
    typeof value !== 'string' ||
    !value ||
    value.length > maximum ||
    value.trim() !== value ||
    /[\u0000-\u001f\u007f]/u.test(value)
  )
    invalid();
  return value;
}

function portablePath(value: Json | undefined): string {
  const name = text(value, 1024);
  if (
    name !== name.normalize('NFC') ||
    /[\\:*?"<>|]/u.test(name) ||
    name.toLowerCase() === '.agent-guard-provenance.json' ||
    name
      .split('/')
      .some(
        part =>
          !part ||
          part === '.' ||
          part === '..' ||
          /[. ]$/u.test(part) ||
          /^(?:con|prn|aux|nul|com[0-9]|lpt[0-9])(?:\.|$)/iu.test(part),
      )
  )
    invalid();
  return name;
}

/** URIs are compared as enrolled strings. The verifier never retrieves their contents. */
function uri(value: Json | undefined): string {
  const name = text(value);
  if (/[\s\\]/u.test(name)) invalid();
  const parsed = new URL(name);
  if (parsed.username || parsed.password) invalid();
  return name;
}

function hexDigest(value: Json | undefined, algorithm: 'sha1' | 'sha256'): string {
  if (typeof value !== 'string' || !(algorithm === 'sha256' ? /^[a-f0-9]{64}$/u : /^[a-f0-9]{40}$/u).test(value))
    invalid();
  return value;
}

function onlyItem(value: Json | undefined): Json {
  if (!Array.isArray(value) || value.length !== 1) invalid();
  return value[0]!;
}

function checkStatement(statement: Json, rule: Enrolled): void {
  const root = fields(statement, ['_type', 'subject', 'predicateType', 'predicate']);
  if (root._type !== 'https://in-toto.io/Statement/v1' || root.predicateType !== 'https://slsa.dev/provenance/v1')
    invalid();
  const subject = fields(onlyItem(root.subject), ['name', 'digest']);
  if (subject.name !== rule.subjectName || fields(subject.digest, ['sha256']).sha256 !== rule.sha256) invalid();

  const predicate = fields(root.predicate, ['buildDefinition', 'runDetails']);
  const definition = fields(
    predicate.buildDefinition,
    ['buildType', 'resolvedDependencies'],
    ['externalParameters', 'internalParameters'],
  );
  if (definition.buildType !== rule.buildType) invalid();
  for (const name of ['externalParameters', 'internalParameters']) {
    if (definition[name] !== undefined && definition[name] !== null) fields(definition[name], []);
  }
  const dependency = fields(onlyItem(definition.resolvedDependencies), ['uri', 'digest']);
  const algorithm = rule.sourceDigest.algorithm;
  if (
    dependency.uri !== rule.sourceUri ||
    fields(dependency.digest, [algorithm])[algorithm] !== rule.sourceDigest.value
  )
    invalid();

  const run = fields(predicate.runDetails, ['builder'], ['metadata']);
  const builder = fields(run.builder, ['id'], ['version']);
  if (builder.id !== rule.builderId) invalid();
  if (builder.version !== undefined) {
    for (const [component, version] of Object.entries(record(builder.version))) {
      text(component, 256);
      text(version, 256);
    }
  }
  if (run.metadata !== undefined) {
    const metadata = fields(run.metadata, [], ['invocationId', 'startedOn', 'finishedOn']);
    for (const value of Object.values(metadata)) text(value);
  }
}

/** Host-enrolled, byte-pinned Ed25519/DSSE admission profile. No key or trust policy comes from the attestation. */
export class BuildProvenancePolicy {
  readonly digest: string;
  readonly #rules = new Map<string, { rule: Enrolled; key: KeyObject }>();

  constructor(input: BuildArtifactPolicy) {
    try {
      const policy = fields(immutableJson(input, 8, 8192, 1024 * 1024), ['artifacts']);
      if (!Array.isArray(policy.artifacts) || !policy.artifacts.length || policy.artifacts.length > 128) invalid();
      const occupied = new Set<string>();
      for (const item of policy.artifacts) {
        const entry = fields(item, [
          'tenantId',
          'path',
          'sha256',
          'subjectName',
          'builderId',
          'buildType',
          'sourceUri',
          'sourceDigest',
          'signerPublicKeyPem',
        ]);
        const source = fields(entry.sourceDigest, ['algorithm', 'value']);
        const algorithm = source.algorithm;
        if (algorithm !== 'sha1' && algorithm !== 'sha256') invalid();
        const { key, signerSha256 } = enrolledSigningKey(entry.signerPublicKeyPem);
        const rule: Enrolled = {
          tenantId: text(entry.tenantId, 512),
          path: portablePath(entry.path),
          sha256: hexDigest(entry.sha256, 'sha256'),
          subjectName: text(entry.subjectName, 1024),
          builderId: uri(entry.builderId),
          buildType: uri(entry.buildType),
          sourceUri: uri(entry.sourceUri),
          sourceDigest: { algorithm, value: hexDigest(source.value, algorithm) },
          signerSha256,
        };
        const location = JSON.stringify([rule.tenantId, rule.path.toLowerCase()]);
        if (occupied.has(location)) invalid();
        occupied.add(location);
        this.#rules.set(JSON.stringify([rule.tenantId, rule.path]), { rule, key });
      }
      const artifacts = [...this.#rules.keys()].sort().map(key => this.#rules.get(key)!.rule);
      this.digest = digestJson(
        immutableJson({ profile: 'agent-guard-build-provenance-v1', artifacts }, 8, 8192, 1024 * 1024),
      );
      Object.freeze(this);
    } catch {
      invalid();
    }
  }

  verify(input: {
    tenantId: string;
    path: string;
    sha256: string;
    attestation: BuildAttestationEnvelope;
  }): BuildProvenanceEvidence {
    try {
      const supplied = fields(immutableJson(input, 8, 64, 192 * 1024), ['tenantId', 'path', 'sha256', 'attestation']);
      const enrolled = this.#rules.get(JSON.stringify([text(supplied.tenantId, 512), portablePath(supplied.path)]));
      if (!enrolled || supplied.sha256 !== enrolled.rule.sha256) invalid();
      const bytes = verifyEnvelopeBytes(
        supplied.attestation,
        MEDIA_TYPE,
        { key: enrolled.key, signerSha256: enrolled.rule.signerSha256 },
        MAX_STATEMENT_BYTES,
      );
      checkStatement(parseEvidenceJson(bytes, MAX_STATEMENT_BYTES), enrolled.rule);
      return Object.freeze({
        policySha256: this.digest,
        statementSha256: hash(bytes),
        signerSha256: enrolled.rule.signerSha256,
      });
    } catch {
      return invalid();
    }
  }
}
