import { createHash, createHmac, randomBytes, randomUUID, timingSafeEqual } from 'node:crypto';
import { lstatSync, mkdirSync, mkdtempSync, realpathSync, rmSync, writeFileSync } from 'node:fs';
import { readWorkspaceInput } from './workspace-input.js';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { GuardError, type Json, type TaskOptions, type ToolDefinition } from '@shieldaai/agent-guard';
import { canonicalJson, digestJson, immutableJson } from '@shieldaai/agent-guard/internal';
import type { DurableExecutor, TaskCredential } from './executor.js';
import { ExecutorError } from './store.js';
import { builtInExecute, hostCallback } from './tool-errors.js';
import {
  BuildProvenancePolicy,
  type BuildArtifactPolicy,
  type BuildAttestationEnvelope,
  type BuildProvenanceEvidence,
} from './build-provenance.js';
import { runDockerSandbox, validateSandboxProfile, writeReviewedExports, type SandboxResult } from './sandbox.js';
import {
  codedError,
  MAX_PATH_COUNT,
  pipelineError,
  portablePathListProblem,
  portablePathProblem,
  PROVENANCE_SIDECAR,
} from './path-rules.js';

export type ArtifactSensitivity = 'public' | 'sensitive';
export interface ArtifactPayload {
  schemaVersion: 1 | 2;
  /** Version 2 binds every receipt, including local derivatives, to the enrolled policy. */
  buildPolicySha256?: string;
  /** Present only on an externally attested build root. */
  buildProvenance?: BuildProvenanceEvidence;
  keyId: string;
  artifactId: string;
  version: number;
  kind: 'file' | 'stdout' | 'stderr';
  path: string;
  sha256: string;
  bytes: number;
  tenantId: string;
  sensitivity: ArtifactSensitivity;
  trust: 'untrusted';
  origin: string;
  issuedAt: number;
  sourceTaskId: string | null;
  lineageTaskIds: readonly string[];
  lineage: readonly string[];
}
export interface SignedArtifactEnvelope {
  payload: ArtifactPayload;
  signature: string;
}
export interface ArtifactInput {
  envelope: SignedArtifactEnvelope;
  contentBase64: string;
}
export interface GovernedSandboxResult {
  result: SandboxResult;
  inputs: SignedArtifactEnvelope[];
  artifacts: SignedArtifactEnvelope[];
  stdout: SignedArtifactEnvelope;
  stderr: SignedArtifactEnvelope;
  sensitive: boolean;
}
type SandboxOptions = Parameters<typeof runDockerSandbox>[0];
export interface GovernedSandboxOptions extends SandboxOptions {
  /** Host classification of the entire command and any raw input. Omission is sensitive. Never model-controlled. */
  inputClassification?: ArtifactSensitivity;
  inputReceipts?: readonly SignedArtifactEnvelope[];
  origin: string;
}
type FileDigest = { path: string; sha256: string };
// Only the registered tool supplies this check; direct host administration has no prepared action.
const checkStagedInputVersion = Symbol('checkStagedInputVersion');
type RegisteredSandboxOptions = GovernedSandboxOptions & {
  [checkStagedInputVersion]: (files: FileDigest[]) => void;
};
const MAX_BYTES = 64 * 1024 * 1024;
const SIDECAR = PROVENANCE_SIDECAR;
/** All receipts of one call together. Each receipt is also bounded on its own by `snapshot`. */
const MAX_RECEIPT_LIST_BYTES = 8 * 1024 * 1024;
const hash = (bytes: Uint8Array) => createHash('sha256').update(bytes).digest('hex');
function fail(detail?: string): never {
  throw pipelineError(
    'ARTIFACT_INVALID',
    'Artifact provenance validation failed',
    detail === undefined ? {} : { detail },
  );
}
function requireAttestation(): never {
  throw new ExecutorError('ARTIFACT_ATTESTATION_REQUIRED');
}
const receiptFields = [
  'artifactId',
  'bytes',
  'issuedAt',
  'keyId',
  'kind',
  'lineage',
  'lineageTaskIds',
  'origin',
  'path',
  'schemaVersion',
  'sensitivity',
  'sha256',
  'sourceTaskId',
  'tenantId',
  'trust',
  'version',
];
function exactFields(value: object, fields: readonly string[]): boolean {
  const keys = Object.keys(value);
  return keys.length === fields.length && fields.every(field => Object.hasOwn(value, field));
}
function text(value: unknown, max = 512): string {
  if (typeof value !== 'string' || !value || value.length > max || /[\u0000-\u001f\u007f]/.test(value)) fail();
  return value;
}
/** A receipt or host-supplied artifact path: the shared portable-path rule. */
function path(value: unknown): string {
  const problem = portablePathProblem(value);
  if (problem) fail(problem);
  return value as string;
}
/** Host-selected sandbox inputs or exports. Same rule and code as the sandbox itself, checked before any work. */
function pathList(value: unknown): string[] {
  const problem = portablePathListProblem(value);
  if (problem)
    throw pipelineError('SANDBOX_PATH_INVALID', 'Expected portable relative file paths without collisions', {
      detail: problem,
    });
  return [...(value as string[])];
}
function list(value: unknown): string[] {
  if (!Array.isArray(value) || value.length > 256) fail();
  const entries = value.map(entry => text(entry));
  if (new Set(entries).size !== entries.length) fail();
  return entries;
}
/** One receipt, or a small configuration object: depth 16, 4,096 values, 256 KiB. */
function snapshot<T>(value: T): T {
  try {
    return immutableJson(value, 16, 4096, 256 * 1024) as T;
  } catch {
    return fail();
  }
}
/**
 * Up to 256 receipts, one per selected path. Every receipt is bounded on its own, so the
 * count never lowers what a single receipt may hold; together they stay under 8 MiB.
 */
function receiptList(value: unknown): SignedArtifactEnvelope[] {
  if (!Array.isArray(value)) fail();
  const count: unknown = Object.getOwnPropertyDescriptor(value, 'length')?.value;
  if (typeof count !== 'number') fail();
  const limit = (detail: string) =>
    pipelineError('ARTIFACT_RECEIPT_LIMIT', 'Input receipts exceed 256 entries or 8 MiB', { detail });
  if (count > MAX_PATH_COUNT) throw limit('RECEIPT_COUNT');
  const receipts: SignedArtifactEnvelope[] = [];
  let bytes = 0;
  for (let index = 0; index < count; index++) {
    // Array.map skips holes; a sparse list must not shrink the set of verified inputs.
    const entry = Object.getOwnPropertyDescriptor(value, index);
    if (!entry || !('value' in entry)) fail();
    const receipt = snapshot(entry.value as SignedArtifactEnvelope);
    if (!receipt || typeof receipt !== 'object' || !receipt.payload || typeof receipt.payload !== 'object') fail();
    bytes += Buffer.byteLength(JSON.stringify(receipt));
    if (bytes > MAX_RECEIPT_LIST_BYTES) throw limit('RECEIPT_BYTES');
    receipts.push(receipt);
  }
  return receipts;
}
/** A view, not a copy: callers hash or write the bytes before returning to their caller. */
function boundedBytes(value: Uint8Array): Buffer {
  if (!(value instanceof Uint8Array) || value.byteLength > MAX_BYTES) fail();
  return Buffer.isBuffer(value) ? value : Buffer.from(value.buffer, value.byteOffset, value.byteLength);
}
function decode(value: string): Buffer {
  if (typeof value !== 'string' || value.length > Math.ceil(MAX_BYTES / 3) * 4) fail();
  const bytes = Buffer.from(value, 'base64');
  if (bytes.length > MAX_BYTES || bytes.toString('base64') !== value) fail();
  return bytes;
}
/** The host workspace itself: an existing real directory, never reached through a symlink. */
function workspaceRoot(value: unknown): string {
  const unavailable = () =>
    pipelineError('SANDBOX_ARGUMENT_INVALID', 'Workspace must be a real directory', {
      detail: 'WORKSPACE_UNAVAILABLE',
    });
  if (typeof value !== 'string' || !value) throw unavailable();
  const root = resolve(value);
  let usable = false;
  try {
    const stat = lstatSync(root);
    usable = !stat.isSymbolicLink() && stat.isDirectory() && realpathSync(root) === root;
  } catch {
    // Reported below without the host path.
  }
  if (!usable) throw unavailable();
  return root;
}
function union(values: readonly string[]): string[] {
  return list([...new Set(values)]);
}
/** The bytes a sandbox stream wrote. Results recorded before the bytes were kept only hold the text. */
function streamBytes(result: SandboxResult, stream: 'stdout' | 'stderr'): Buffer {
  if (!result || typeof result !== 'object') fail();
  const encoded: unknown = result[`${stream}Base64`];
  if (encoded !== undefined) return decode(encoded as string);
  const text: unknown = result[stream];
  if (typeof text !== 'string' || text.length > MAX_BYTES) fail();
  return Buffer.from(text);
}
type VerifyKnownDigest = (
  envelope: SignedArtifactEnvelope,
  content: Buffer,
  tenantId: string,
  executor: DurableExecutor | undefined,
  sha256: string,
) => Readonly<ArtifactPayload>;
// Lets this module's sandbox tool verify bytes it has already hashed without a public method.
const verifyKnownDigest = new WeakMap<ArtifactBroker, VerifyKnownDigest>();
/** Host-only signing authority. Store its stable random key outside every agent and guest environment. */
export class ArtifactBroker {
  readonly #key: Buffer;
  readonly #keyId: string;
  readonly #clock: () => number;
  readonly #buildPolicy: BuildProvenancePolicy | undefined;
  #closed = false;
  constructor(options: { key: Uint8Array; keyId: string; clock?: () => number; buildPolicy?: BuildArtifactPolicy }) {
    if (
      !options ||
      typeof options !== 'object' ||
      !(options.key instanceof Uint8Array) ||
      options.key.byteLength !== 32 ||
      (options.clock !== undefined && typeof options.clock !== 'function')
    )
      fail();
    this.#key = Buffer.from(options.key);
    this.#keyId = text(options.keyId);
    this.#clock = options.clock ?? Date.now;
    this.#buildPolicy = options.buildPolicy === undefined ? undefined : new BuildProvenancePolicy(options.buildPolicy);
    verifyKnownDigest.set(this, (envelope, content, tenantId, executor, sha256) =>
      this.#verify(envelope, content, tenantId, executor, sha256),
    );
  }
  get buildPolicySha256(): string | undefined {
    return this.#buildPolicy?.digest;
  }
  close(): void {
    this.#key.fill(0);
    this.#closed = true;
  }
  /** Check host authority before reading inputs or starting work, including commands with no inputs. */
  assertOpen(): void {
    if (this.#closed) throw new ExecutorError('ARTIFACT_BROKER_CLOSED');
  }
  #signature(payload: ArtifactPayload): Buffer {
    this.assertOpen();
    return createHmac('sha256', this.#key)
      .update(payload.schemaVersion === 2 ? 'agent-guard-artifact-v2\0' : 'agent-guard-artifact-v1\0')
      .update(canonicalJson(payload as unknown as Json))
      .digest();
  }
  #sign(
    bytes: Buffer,
    fields: Omit<
      ArtifactPayload,
      'schemaVersion' | 'keyId' | 'artifactId' | 'sha256' | 'bytes' | 'issuedAt' | 'trust' | 'buildPolicySha256'
    >,
    executor?: DurableExecutor,
    /** Digest of `bytes` when the caller has already computed it: content is hashed once per receipt. */
    sha256: string = hash(bytes),
  ): SignedArtifactEnvelope {
    const issuedAt = hostCallback(() => this.#clock());
    if (!Number.isSafeInteger(issuedAt) || issuedAt < 0) fail();
    const payload: ArtifactPayload = {
      ...fields,
      schemaVersion: this.#buildPolicy ? 2 : 1,
      ...(this.#buildPolicy ? { buildPolicySha256: this.#buildPolicy.digest } : {}),
      keyId: this.#keyId,
      artifactId: randomUUID(),
      sha256,
      bytes: bytes.length,
      issuedAt,
      trust: 'untrusted',
    };
    const envelope = snapshot({
      payload,
      signature: this.#signature(payload).toString('hex'),
    });
    this.#verify(envelope, bytes, payload.tenantId, executor, sha256);
    return envelope;
  }
  /** Explicit trusted-host admission; unknown/raw content is sensitive by default. Does not establish trustworthy instructions. */
  classifyArtifact(options: {
    content: Uint8Array;
    path: string;
    tenantId: string;
    origin: string;
    sensitivity?: ArtifactSensitivity;
  }): SignedArtifactEnvelope {
    this.assertOpen();
    if (this.#buildPolicy) requireAttestation();
    const sensitivity = options.sensitivity ?? 'sensitive';
    if (sensitivity !== 'public' && sensitivity !== 'sensitive') fail();
    // The receipt keeps only a digest, so no private copy of the content is needed.
    return this.#sign(boundedBytes(options.content), {
      path: path(options.path),
      tenantId: text(options.tenantId),
      origin: text(options.origin),
      sensitivity,
      kind: 'file',
      sourceTaskId: null,
      lineageTaskIds: [],
      lineage: [],
      version: 1,
    });
  }
  /** Verify external build evidence against host enrollment before minting a sensitive root receipt. */
  admitBuildArtifact(options: {
    content: Uint8Array;
    path: string;
    tenantId: string;
    attestation: BuildAttestationEnvelope;
  }): SignedArtifactEnvelope {
    this.assertOpen();
    if (!this.#buildPolicy) requireAttestation();
    const name = path(options.path);
    const tenantId = text(options.tenantId);
    const bytes = boundedBytes(options.content);
    const sha256 = hash(bytes);
    const buildProvenance = this.#buildPolicy.verify({
      tenantId,
      path: name,
      sha256,
      attestation: options.attestation,
    });
    return this.#sign(
      bytes,
      {
        path: name,
        tenantId,
        origin: 'verified-build',
        sensitivity: 'sensitive',
        kind: 'file',
        sourceTaskId: null,
        lineageTaskIds: [],
        lineage: [],
        version: 1,
        buildProvenance,
      },
      undefined,
      sha256,
    );
  }
  #verifyReceiptProfile(payload: ArtifactPayload): void {
    if (!this.#buildPolicy) {
      if (payload.schemaVersion !== 1 || !exactFields(payload, receiptFields)) fail();
      return;
    }
    if (payload.schemaVersion !== 2 || payload.buildPolicySha256 !== this.#buildPolicy.digest) fail();
    const fields = [...receiptFields, 'buildPolicySha256'];
    if (payload.sourceTaskId === null) {
      const evidence = payload.buildProvenance;
      if (
        !evidence ||
        typeof evidence !== 'object' ||
        !exactFields(evidence, ['policySha256', 'statementSha256', 'signerSha256']) ||
        evidence.policySha256 !== this.#buildPolicy.digest ||
        typeof evidence.statementSha256 !== 'string' ||
        !/^[a-f0-9]{64}$/.test(evidence.statementSha256) ||
        typeof evidence.signerSha256 !== 'string' ||
        !/^[a-f0-9]{64}$/.test(evidence.signerSha256) ||
        payload.kind !== 'file' ||
        payload.version !== 1 ||
        payload.sensitivity !== 'sensitive' ||
        payload.origin !== 'verified-build'
      )
        fail();
      fields.push('buildProvenance');
    }
    if (!exactFields(payload, fields)) fail();
  }
  /** Validate signed data without creating tasks or writing files. Source receipts require the owning executor. */
  verifyArtifact(
    envelope: SignedArtifactEnvelope,
    content: Uint8Array,
    tenantId: string,
    executor?: DurableExecutor,
  ): Readonly<ArtifactPayload> {
    this.assertOpen();
    return this.#verify(envelope, boundedBytes(content), tenantId, executor);
  }
  #verify(
    envelope: SignedArtifactEnvelope,
    bytes: Buffer,
    tenantId: string,
    executor: DurableExecutor | undefined,
    /** Digest of `bytes` when the caller has just computed it. */
    sha256?: string,
  ): Readonly<ArtifactPayload> {
    this.assertOpen();
    const value = snapshot(envelope);
    if (!value || typeof value !== 'object' || Object.keys(value).sort().join(',') !== 'payload,signature') fail();
    const p = value.payload;
    if (!p || typeof p !== 'object') fail();
    this.#verifyReceiptProfile(p);
    if (
      p.keyId !== this.#keyId ||
      p.trust !== 'untrusted' ||
      !['file', 'stdout', 'stderr'].includes(p.kind) ||
      !['public', 'sensitive'].includes(p.sensitivity)
    )
      fail();
    text(p.artifactId);
    text(p.origin);
    text(p.tenantId);
    path(p.path);
    if (
      p.tenantId !== tenantId ||
      !Number.isSafeInteger(p.version) ||
      p.version < 1 ||
      p.version > 1_000_000 ||
      !Number.isSafeInteger(p.issuedAt) ||
      p.issuedAt < 0 ||
      !Number.isSafeInteger(p.bytes) ||
      p.bytes < 0 ||
      p.bytes > MAX_BYTES ||
      !/^[a-f0-9]{64}$/.test(p.sha256)
    )
      fail();
    list(p.lineage);
    list(p.lineageTaskIds);
    if (p.sourceTaskId !== null && (!p.lineageTaskIds.includes(text(p.sourceTaskId)) || !executor)) fail();
    if (
      typeof value.signature !== 'string' ||
      !/^[a-f0-9]{64}$/.test(value.signature) ||
      !timingSafeEqual(Buffer.from(value.signature, 'hex'), this.#signature(p))
    )
      fail();
    if (p.bytes !== bytes.length || p.sha256 !== (sha256 ?? hash(bytes))) fail();
    for (const taskId of p.lineageTaskIds) {
      if (!executor || executor.assertProvenance(taskId).tenantId !== tenantId) fail();
    }
    return p;
  }
  /** Host chooses grants; artifact data cannot grant authority. All imports validate before task creation. */
  createTaskFromArtifacts(
    executor: DurableExecutor,
    options: TaskOptions,
    inputs: readonly ArtifactInput[],
  ): TaskCredential {
    this.assertOpen();
    let task: TaskOptions;
    try {
      task = immutableJson(options) as unknown as TaskOptions;
    } catch {
      throw new GuardError('INVALID_INPUT');
    }
    if (!task || typeof task !== 'object') throw new GuardError('INVALID_INPUT');
    if (!Array.isArray(inputs)) fail();
    const count = Object.getOwnPropertyDescriptor(inputs, 'length')?.value;
    if (!Number.isSafeInteger(count) || count < 1 || count > 256) fail();
    const payloads: Readonly<ArtifactPayload>[] = [];
    // Array.map skips holes. A sparse batch must never create an unlabeled task.
    for (let index = 0; index < count; index++) {
      const entry = Object.getOwnPropertyDescriptor(inputs, index);
      if (!entry || !('value' in entry) || !entry.value || typeof entry.value !== 'object') fail();
      const envelope = Object.getOwnPropertyDescriptor(entry.value, 'envelope');
      const content = Object.getOwnPropertyDescriptor(entry.value, 'contentBase64');
      if (!envelope || !('value' in envelope) || !content || !('value' in content)) fail();
      payloads.push(this.verifyArtifact(envelope.value, decode(content.value), task.tenantId, executor));
    }
    const sources = union(payloads.flatMap(p => (p.sourceTaskId === null ? [] : [p.sourceTaskId])));
    if (sources.length > 1)
      throw pipelineError('ARTIFACT_INVALID', 'Artifact imports require a single producing task', {
        detail: 'MULTIPLE_SOURCE_TASKS',
      });
    const sensitive = payloads.some(
      p => p.sensitivity !== 'public' || p.lineageTaskIds.some(id => executor.assertProvenance(id).sensitive),
    );
    return executor.createTask(task, {
      sensitive,
      ...(sources[0] ? { sourceTaskId: sources[0] } : {}),
    });
  }
  async runGovernedSandbox(
    executor: DurableExecutor,
    taskId: string,
    options: GovernedSandboxOptions,
  ): Promise<GovernedSandboxResult> {
    this.assertOpen();
    const initial = executor.assertProvenance(taskId);
    if (!options || typeof options !== 'object') fail();
    const profile = validateSandboxProfile(options.profile);
    text(options.origin);
    if (
      options.inputClassification !== undefined &&
      options.inputClassification !== 'public' &&
      options.inputClassification !== 'sensitive'
    )
      fail();
    // Every selected path, inputs and exports alike, is checked before a byte is read,
    // the task is tainted or a container starts. The run cannot fail on a path afterwards.
    const names = pathList(options.inputFiles);
    const exportNames = pathList(options.exportFiles ?? []);
    const receipts = receiptList(options.inputReceipts ?? []);
    if (receipts.length > names.length) fail();
    if (this.#buildPolicy && receipts.length !== names.length) requireAttestation();
    const receiptNames = receipts.map(receipt => path(receipt.payload.path));
    if (new Set(receiptNames).size !== receiptNames.length || receiptNames.some(name => !names.includes(name))) fail();
    const root = workspaceRoot(options.workspace);
    let staging: string | undefined;
    let failed = false,
      failure: unknown;
    try {
      staging = realpathSync(mkdtempSync(join(tmpdir(), 'agent-guard-artifacts-')));
      let remaining = profile.maxInputBytes;
      const parents: Readonly<ArtifactPayload>[] = [];
      const rawInputs: { name: string; bytes: Buffer; sha256: string }[] = [];
      const inputs: SignedArtifactEnvelope[] = [...receipts];
      // Each input is hashed once. The same digest serves the approved-version check,
      // receipt verification and the receipt signed for a raw input.
      const stagedInputs = names.map(name => {
        const bytes = readWorkspaceInput(root, name, remaining);
        remaining -= bytes.length;
        return { name, bytes, sha256: hash(bytes) };
      });
      // Hash and copy the same private buffers. A second read of the source workspace
      // here would let a file change between approval validation and guest staging.
      (options as Partial<RegisteredSandboxOptions>)[checkStagedInputVersion]?.(
        stagedInputs.map(({ name, sha256 }) => ({ path: name, sha256 })),
      );
      for (const { name, bytes, sha256 } of stagedInputs) {
        const receipt = receipts.find(candidate => candidate.payload.path === name);
        if (receipt) parents.push(this.#verify(receipt, bytes, initial.tenantId, executor, sha256));
        else rawInputs.push({ name, bytes, sha256 });
        const target = join(staging, ...name.split('/'));
        mkdirSync(dirname(target), { recursive: true, mode: 0o700 });
        writeFileSync(target, bytes, { flag: 'wx', mode: 0o600 });
      }
      const sensitive =
        options.inputClassification !== 'public' ||
        parents.some(
          p => p.sensitivity !== 'public' || p.lineageTaskIds.some(id => executor.assertProvenance(id).sensitive),
        );
      // Persist taint before any bytes or command reach the shell, including failed executions.
      this.assertOpen();
      if (sensitive) executor.markSensitive(taskId);
      const lineageTaskIds = union(executor.provenanceTaskIds(taskId));
      if (parents.some(p => p.lineageTaskIds.some(id => !lineageTaskIds.includes(id))))
        throw pipelineError(
          'ARTIFACT_INVALID',
          'Import source artifacts through createTaskFromArtifacts before sandbox use',
          { detail: 'LINEAGE_NOT_IMPORTED' },
        );
      for (const raw of rawInputs) {
        const receipt = this.#sign(
          raw.bytes,
          {
            path: raw.name,
            kind: 'file',
            tenantId: initial.tenantId,
            origin: options.origin,
            sensitivity: executor.assertProvenance(taskId).sensitive ? 'sensitive' : 'public',
            sourceTaskId: taskId,
            lineageTaskIds,
            lineage: [],
            version: 1,
          },
          executor,
          raw.sha256,
        );
        inputs.push(receipt);
        parents.push(receipt.payload);
      }
      const lineage = union(parents.flatMap(p => [p.artifactId, ...p.lineage]));
      const version = 1 + Math.max(0, ...parents.map(p => p.version));
      if (version > 1_000_000) fail();
      const launch = {
        profile,
        workspace: staging,
        inputFiles: names,
        command: options.command,
        exportFiles: exportNames,
        ...(options.signal ? { signal: options.signal } : {}),
      };
      this.assertOpen();
      const result = await runDockerSandbox(launch);
      for (const source of lineageTaskIds) {
        const state = executor.assertProvenance(source);
        if (state.tenantId !== initial.tenantId) fail();
        if (state.sensitive) executor.markSensitive(taskId);
      }
      const finalSensitive = executor.assertProvenance(taskId).sensitive;
      const fields = {
        version,
        tenantId: initial.tenantId,
        origin: options.origin,
        sensitivity: finalSensitive ? ('sensitive' as const) : ('public' as const),
        sourceTaskId: taskId,
        lineageTaskIds,
        lineage,
      };
      const sign = (bytes: Buffer, name: string, kind: ArtifactPayload['kind'], sha256?: string) =>
        this.#sign(bytes, { ...fields, path: name, kind }, executor, sha256);
      // #sign validates locally; source checks have just succeeded and are rechecked on every import/export.
      // The archive reader hashed these exact bytes in this call, so its digest is reused.
      const artifacts = result.exports.map(file => {
        const bytes = decode(file.contentBase64);
        if (bytes.length !== file.size || !/^[a-f0-9]{64}$/.test(file.sha256)) fail();
        return sign(bytes, path(file.path), 'file', file.sha256);
      });
      return {
        result,
        inputs,
        artifacts,
        // Receipts cover the bytes the command wrote, not a re-encoding of their text view.
        stdout: sign(streamBytes(result, 'stdout'), 'stdout.txt', 'stdout'),
        stderr: sign(streamBytes(result, 'stderr'), 'stderr.txt', 'stderr'),
        sensitive: finalSensitive,
      };
    } catch (error) {
      failed = true;
      failure = codedError(error, 'SANDBOX_FAILED', 'Sandbox run failed');
      throw failure;
    } finally {
      try {
        if (staging !== undefined) rmSync(staging, { recursive: true, force: true });
      } catch {
        // Report the leftover private copies without replacing the run's own error.
        throw pipelineError(
          'SANDBOX_CLEANUP_FAILED',
          'Sandbox cleanup failed; remove the private staging directory before continuing',
          { detail: 'STAGING_LEFT', ...(failed ? { cause: failure } : {}) },
        );
      }
    }
  }
  /** Host review is exact hashes/paths. Writes a fresh private directory plus signed provenance sidecar. */
  writeReviewedArtifacts(
    executor: DurableExecutor,
    output: GovernedSandboxResult,
    approved: { path: string; sha256: string }[],
    destination: string,
  ): string[] {
    this.assertOpen();
    let receipts: SignedArtifactEnvelope[];
    try {
      if (!Array.isArray(approved) || !approved.length || approved.length > MAX_PATH_COUNT) fail();
      const expectedTenant = output.stdout.payload.tenantId;
      const expectedSource = output.stdout.payload.sourceTaskId;
      receipts = approved.map(selection => {
        const receipt = output.artifacts.find(item => item.payload.path === selection.path);
        const file = output.result.exports.find(item => item.path === selection.path);
        if (
          !receipt ||
          !file ||
          receipt.payload.kind !== 'file' ||
          selection.sha256 !== receipt.payload.sha256 ||
          receipt.payload.tenantId !== expectedTenant ||
          receipt.payload.sourceTaskId !== expectedSource
        )
          fail();
        this.verifyArtifact(receipt, decode(file.contentBase64), receipt.payload.tenantId, executor);
        return receipt;
      });
      if (
        output.stdout.payload.kind !== 'stdout' ||
        output.stderr.payload.kind !== 'stderr' ||
        output.stderr.payload.sourceTaskId !== expectedSource
      )
        fail();
      const tenantId = receipts[0]!.payload.tenantId;
      this.verifyArtifact(output.stdout, streamBytes(output.result, 'stdout'), tenantId, executor);
      this.verifyArtifact(output.stderr, streamBytes(output.result, 'stderr'), tenantId, executor);
    } catch (error) {
      // A malformed result object is a failed validation, not a TypeError.
      throw codedError(error, 'ARTIFACT_INVALID', 'Artifact provenance validation failed');
    }
    const written = writeReviewedExports(output.result, approved, destination);
    try {
      writeFileSync(
        join(destination, SIDECAR),
        JSON.stringify({
          artifacts: receipts,
          stdout: output.stdout,
          stderr: output.stderr,
        }),
        { flag: 'wx', mode: 0o600 },
      );
    } catch (error) {
      rmSync(destination, { recursive: true, force: true });
      throw codedError(
        error,
        'SANDBOX_EXPORT_DESTINATION_UNAVAILABLE',
        'The reviewed export destination could not be created',
      );
    }
    return written;
  }
}
/** Administration API: never expose the broker or inputClassification directly to the agent. */
export function runGovernedSandbox(
  executor: DurableExecutor,
  taskId: string,
  options: GovernedSandboxOptions & { broker: ArtifactBroker },
): Promise<GovernedSandboxResult> {
  return options.broker.runGovernedSandbox(executor, taskId, options);
}

export interface SandboxToolOptions {
  name: string;
  executor: DurableExecutor;
  broker: ArtifactBroker;
  profile: GovernedSandboxOptions['profile'];
  workspace: string;
  inputFiles: string[];
  exportFiles?: string[];
  tenantId: string;
  resourceId: string;
  origin: string;
  inputClassification?: ArtifactSensitivity;
  inputReceipts?: readonly SignedArtifactEnvelope[];
  requiresApproval?: boolean;
  /** Host retains full labeled output and returns an opaque retrieval ID, never a public URL. */
  onResult(output: GovernedSandboxResult, context: { taskId: string }): string | Promise<string>;
}
/**
 * The sandbox tool's own refusals keep their code through execute(). An error from a host callback
 * (`onResult`, the broker's clock) is a tool failure whatever its code: both run through hostCallback().
 */
const SANDBOX_TOOL_CODES = [
  /^(?:SANDBOX|ARTIFACT|WORKSPACE_INPUT|BUILD_PROVENANCE)_[A-Z_]+$/,
  'TOOL_CHANGED',
  'TASK_REVOKED',
  'EXECUTION_ABORTED',
];
/** Register and approve this definition to place every shell invocation behind durable admission. */
export function createSandboxTool(options: SandboxToolOptions): ToolDefinition {
  if (!options || typeof options !== 'object' || !(options.broker instanceof ArtifactBroker)) fail();
  const broker = options.broker;
  broker.assertOpen();
  const verify = verifyKnownDigest.get(broker);
  const executor = options.executor,
    onResult = options.onResult;
  if (typeof onResult !== 'function' || typeof options.workspace !== 'string' || !verify) fail();
  // Receipts are bounded one by one, so a receipt for each of 256 inputs fits. The digest
  // below covers the same value as before: the configuration with its receipts.
  const config = Object.freeze({
    ...snapshot({
      name: text(options.name),
      profile: validateSandboxProfile(options.profile),
      workspace: resolve(options.workspace),
      ...(broker.buildPolicySha256 ? { buildPolicySha256: broker.buildPolicySha256 } : {}),
      inputFiles: pathList(options.inputFiles),
      exportFiles: pathList(options.exportFiles ?? []),
      tenantId: text(options.tenantId),
      resourceId: text(options.resourceId),
      origin: text(options.origin),
      inputClassification: options.inputClassification ?? 'sensitive',
      requiresApproval: options.requiresApproval ?? true,
    }),
    inputReceipts: Object.freeze(receiptList(options.inputReceipts ?? [])),
  });
  if (!['public', 'sensitive'].includes(config.inputClassification) || typeof config.requiresApproval !== 'boolean')
    fail();
  if (config.buildPolicySha256) {
    const selected = new Set(config.inputReceipts.map(receipt => receipt.payload.path));
    if (
      selected.size !== config.inputReceipts.length ||
      selected.size !== config.inputFiles.length ||
      config.inputFiles.some(name => !selected.has(name))
    )
      requireAttestation();
  }
  const configDigest = digestJson(config as unknown as Json);
  const versionKey = randomBytes(32);
  function parse(value: Json): Json {
    if (!value || typeof value !== 'object' || Array.isArray(value) || Object.keys(value).join(',') !== 'command')
      throw new GuardError('ARGUMENT_INVALID');
    const argv = (value as { command: Json }).command;
    if (
      !Array.isArray(argv) ||
      !argv.length ||
      argv.length > 128 ||
      argv.some(arg => typeof arg !== 'string' || arg.includes('\0') || Buffer.byteLength(arg) > 8192) ||
      Buffer.byteLength(JSON.stringify(argv)) > 128 * 1024
    )
      throw new GuardError('ARGUMENT_INVALID');
    return { command: argv };
  }
  function versionForFiles(files: FileDigest[]): string {
    return `hmac-sha256:${createHmac('sha256', versionKey).update(canonicalJson({ configDigest, files })).digest('hex')}`;
  }
  function resourceVersion(): string {
    broker.assertOpen();
    workspaceRoot(config.workspace);
    let remaining = config.profile.maxInputBytes;
    const files = config.inputFiles.map(name => {
      const bytes = readWorkspaceInput(config.workspace, name, remaining);
      remaining -= bytes.length;
      const sha256 = hash(bytes);
      if (config.buildPolicySha256) {
        const receipt = config.inputReceipts.find(item => item.payload.path === name);
        if (!receipt) requireAttestation();
        verify!(receipt, bytes, config.tenantId, executor, sha256);
      }
      return { path: name, sha256 };
    });
    return versionForFiles(files);
  }
  const logs = (bytes: Buffer, receipt: SignedArtifactEnvelope): Json => {
    return {
      text: bytes.subarray(0, 16 * 1024).toString('utf8'),
      truncated: bytes.length > 16 * 1024,
      artifactId: receipt.payload.artifactId,
      sha256: receipt.payload.sha256,
      sensitivity: receipt.payload.sensitivity,
    };
  };
  return {
    name: config.name,
    description: 'Run approved command arguments in a bounded Linux container; retain signed output with the host.',
    inputSchema: {
      type: 'object',
      properties: {
        command: {
          type: 'array',
          items: { type: 'string', maxLength: 8192 },
          minItems: 1,
          maxItems: 128,
        },
      },
      required: ['command'],
      additionalProperties: false,
    },
    metadata: {
      adapter: 'governed-docker-sandbox-v1',
      configurationDigest: configDigest,
      image: config.profile.image,
    },
    requiresApproval: config.requiresApproval,
    parse,
    resolve: (args, task) => {
      parse(args);
      if (task.tenantId !== config.tenantId) throw new GuardError('TENANT_DENIED');
      return {
        resourceId: config.resourceId,
        tenantId: config.tenantId,
        resourceVersion: resourceVersion(),
        sensitive:
          config.inputClassification !== 'public' ||
          config.inputReceipts.some(receipt => receipt.payload.sensitivity !== 'public'),
      };
    },
    execute: builtInExecute(async (args, context) => {
      const parsed = parse(args) as { command: string[] };
      if (context.task.tenantId !== config.tenantId || context.action.resourceId !== config.resourceId)
        throw new GuardError('TOOL_CHANGED');
      if (context.signal.aborted) throw new GuardError('EXECUTION_ABORTED');
      const launch: RegisteredSandboxOptions = {
        profile: config.profile,
        workspace: config.workspace,
        inputFiles: config.inputFiles,
        exportFiles: config.exportFiles,
        command: parsed.command,
        origin: config.origin,
        inputClassification: config.inputClassification,
        inputReceipts: config.inputReceipts,
        signal: context.signal,
        [checkStagedInputVersion](files) {
          if (versionForFiles(files) !== context.action.resourceVersion) throw new GuardError('TOOL_CHANGED');
        },
      };
      const output = await broker.runGovernedSandbox(executor, context.task.id, launch);
      if (context.signal.aborted) throw new GuardError('EXECUTION_ABORTED');
      const resultId = text(await hostCallback(() => onResult(output, { taskId: context.task.id })));
      return {
        value: {
          resultId,
          exitCode: output.result.exitCode,
          sensitive: output.sensitive,
          stdout: logs(streamBytes(output.result, 'stdout'), output.stdout),
          stderr: logs(streamBytes(output.result, 'stderr'), output.stderr),
          artifactIds: output.artifacts.map(receipt => receipt.payload.artifactId),
        },
      };
    }, SANDBOX_TOOL_CODES),
  };
}
