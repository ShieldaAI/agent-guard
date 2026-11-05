import {
  createHash,
  createHmac,
  randomBytes,
  randomUUID,
  timingSafeEqual,
} from "node:crypto";
import {
  lstatSync,
  mkdirSync,
  mkdtempSync,
  realpathSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { readWorkspaceInput } from './workspace-input.js';
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import {
  canonicalJson,
  digestJson,
  GuardError,
  immutableJson,
  type Json,
  type TaskOptions,
  type ToolDefinition,
} from "@shieldaai/agent-guard";
import type { DurableExecutor, TaskCredential } from "./executor.js";
import { ExecutorError } from "./store.js";
import {
  BuildProvenancePolicy,
  type BuildArtifactPolicy,
  type BuildAttestationEnvelope,
  type BuildProvenanceEvidence,
} from "./build-provenance.js";
import {
  runDockerSandbox,
  validateSandboxProfile,
  writeReviewedExports,
  type SandboxResult,
} from "./sandbox.js";

export type ArtifactSensitivity = "public" | "sensitive";
export interface ArtifactPayload {
  schemaVersion: 1 | 2;
  /** Version 2 binds every receipt, including local derivatives, to the enrolled policy. */
  buildPolicySha256?: string;
  /** Present only on an externally attested build root. */
  buildProvenance?: BuildProvenanceEvidence;
  keyId: string;
  artifactId: string;
  version: number;
  kind: "file" | "stdout" | "stderr";
  path: string;
  sha256: string;
  bytes: number;
  tenantId: string;
  sensitivity: ArtifactSensitivity;
  trust: "untrusted";
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
const checkStagedInputVersion = Symbol("checkStagedInputVersion");
type RegisteredSandboxOptions = GovernedSandboxOptions & {
  [checkStagedInputVersion]: (files: FileDigest[]) => void;
};
const MAX_BYTES = 64 * 1024 * 1024;
const SIDECAR = ".agent-guard-provenance.json";
const hash = (bytes: Uint8Array) =>
  createHash("sha256").update(bytes).digest("hex");
function fail(): never {
  throw new Error("Artifact provenance validation failed");
}
function requireAttestation(): never {
  throw new ExecutorError("ARTIFACT_ATTESTATION_REQUIRED");
}
const receiptFields = [
  "artifactId", "bytes", "issuedAt", "keyId", "kind", "lineage", "lineageTaskIds",
  "origin", "path", "schemaVersion", "sensitivity", "sha256", "sourceTaskId",
  "tenantId", "trust", "version",
];
function exactFields(value: object, fields: readonly string[]): boolean {
  const keys = Object.keys(value);
  return keys.length === fields.length && fields.every((field) => Object.hasOwn(value, field));
}
function text(value: unknown, max = 512): string {
  if (
    typeof value !== "string" ||
    !value ||
    value.length > max ||
    /[\u0000-\u001f\u007f]/.test(value)
  )
    fail();
  return value;
}
function path(value: unknown): string {
  const name = text(value, 1024);
  if (
    name !== name.normalize("NFC") ||
    name.startsWith("/") ||
    /[\\:*?"<>|]/.test(name) ||
    name
      .split("/")
      .some(
        (part) =>
          !part ||
          part === "." ||
          part === ".." ||
          /[. ]$/.test(part) ||
          /^(?:con|prn|aux|nul|com[0-9]|lpt[0-9])(?:\.|$)/i.test(part),
      ) ||
    name === SIDECAR
  )
    fail();
  return name;
}
function list(value: unknown): string[] {
  if (!Array.isArray(value) || value.length > 256) fail();
  const entries = value.map((entry) => text(entry));
  if (new Set(entries).size !== entries.length) fail();
  return entries;
}
function snapshot<T>(value: T): T {
  return immutableJson(value, 16, 4096, 256 * 1024) as T;
}
function boundedBytes(value: Uint8Array): Buffer {
  if (!(value instanceof Uint8Array) || value.byteLength > MAX_BYTES) fail();
  return Buffer.from(value);
}
function decode(value: string): Buffer {
  if (typeof value !== "string" || value.length > Math.ceil(MAX_BYTES / 3) * 4)
    fail();
  const bytes = Buffer.from(value, "base64");
  if (bytes.length > MAX_BYTES || bytes.toString("base64") !== value) fail();
  return bytes;
}
function union(values: readonly string[]): string[] {
  return list([...new Set(values)]);
}
/** Host-only signing authority. Store its stable random key outside every agent and guest environment. */
export class ArtifactBroker {
  readonly #key: Buffer;
  readonly #keyId: string;
  readonly #clock: () => number;
  readonly #buildPolicy: BuildProvenancePolicy | undefined;
  #closed = false;
  constructor(options: {
    key: Uint8Array;
    keyId: string;
    clock?: () => number;
    buildPolicy?: BuildArtifactPolicy;
  }) {
    if (!(options.key instanceof Uint8Array) || options.key.byteLength !== 32)
      fail();
    this.#key = Buffer.from(options.key);
    this.#keyId = text(options.keyId);
    this.#clock = options.clock ?? Date.now;
    this.#buildPolicy = options.buildPolicy === undefined
      ? undefined : new BuildProvenancePolicy(options.buildPolicy);
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
    if (this.#closed) throw new ExecutorError("ARTIFACT_BROKER_CLOSED");
  }
  #signature(payload: ArtifactPayload): Buffer {
    this.assertOpen();
    return createHmac("sha256", this.#key)
      .update(payload.schemaVersion === 2 ? "agent-guard-artifact-v2\0" : "agent-guard-artifact-v1\0")
      .update(canonicalJson(payload as unknown as Json))
      .digest();
  }
  #sign(
    bytes: Buffer,
    fields: Omit<
      ArtifactPayload,
      | "schemaVersion"
      | "keyId"
      | "artifactId"
      | "sha256"
      | "bytes"
      | "issuedAt"
      | "trust"
      | "buildPolicySha256"
    >,
    executor?: DurableExecutor,
  ): SignedArtifactEnvelope {
    const issuedAt = this.#clock();
    if (!Number.isSafeInteger(issuedAt) || issuedAt < 0) fail();
    const payload: ArtifactPayload = {
      ...fields,
      schemaVersion: this.#buildPolicy ? 2 : 1,
      ...(this.#buildPolicy ? { buildPolicySha256: this.#buildPolicy.digest } : {}),
      keyId: this.#keyId,
      artifactId: randomUUID(),
      sha256: hash(bytes),
      bytes: bytes.length,
      issuedAt,
      trust: "untrusted",
    };
    const envelope = snapshot({
      payload,
      signature: this.#signature(payload).toString("hex"),
    });
    this.verifyArtifact(envelope, bytes, payload.tenantId, executor);
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
    const sensitivity = options.sensitivity ?? "sensitive";
    if (sensitivity !== "public" && sensitivity !== "sensitive") fail();
    return this.#sign(boundedBytes(options.content), {
      path: path(options.path),
      tenantId: text(options.tenantId),
      origin: text(options.origin),
      sensitivity,
      kind: "file",
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
    const buildProvenance = this.#buildPolicy.verify({
      tenantId, path: name, sha256: hash(bytes), attestation: options.attestation,
    });
    return this.#sign(bytes, {
      path: name, tenantId, origin: "verified-build", sensitivity: "sensitive",
      kind: "file", sourceTaskId: null, lineageTaskIds: [], lineage: [],
      version: 1, buildProvenance,
    });
  }
  #verifyReceiptProfile(payload: ArtifactPayload): void {
    if (!this.#buildPolicy) {
      if (payload.schemaVersion !== 1 || !exactFields(payload, receiptFields)) fail();
      return;
    }
    if (payload.schemaVersion !== 2 || payload.buildPolicySha256 !== this.#buildPolicy.digest) fail();
    const fields = [...receiptFields, "buildPolicySha256"];
    if (payload.sourceTaskId === null) {
      const evidence = payload.buildProvenance;
      if (!evidence || typeof evidence !== "object" ||
          !exactFields(evidence, ["policySha256", "statementSha256", "signerSha256"]) ||
          evidence.policySha256 !== this.#buildPolicy.digest ||
          typeof evidence.statementSha256 !== "string" || !/^[a-f0-9]{64}$/.test(evidence.statementSha256) ||
          typeof evidence.signerSha256 !== "string" || !/^[a-f0-9]{64}$/.test(evidence.signerSha256) ||
          payload.kind !== "file" || payload.version !== 1 || payload.sensitivity !== "sensitive" ||
          payload.origin !== "verified-build") fail();
      fields.push("buildProvenance");
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
    const value = snapshot(envelope);
    if (
      !value ||
      typeof value !== "object" ||
      Object.keys(value).sort().join(",") !== "payload,signature"
    )
      fail();
    const p = value.payload;
    if (!p || typeof p !== "object") fail();
    this.#verifyReceiptProfile(p);
    if (
      p.keyId !== this.#keyId ||
      p.trust !== "untrusted" ||
      !["file", "stdout", "stderr"].includes(p.kind) ||
      !["public", "sensitive"].includes(p.sensitivity)
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
    if (
      p.sourceTaskId !== null &&
      (!p.lineageTaskIds.includes(text(p.sourceTaskId)) || !executor)
    )
      fail();
    if (
      typeof value.signature !== "string" ||
      !/^[a-f0-9]{64}$/.test(value.signature) ||
      !timingSafeEqual(Buffer.from(value.signature, "hex"), this.#signature(p))
    )
      fail();
    const bytes = boundedBytes(content);
    if (p.bytes !== bytes.length || p.sha256 !== hash(bytes)) fail();
    for (const taskId of p.lineageTaskIds) {
      if (!executor || executor.assertProvenance(taskId).tenantId !== tenantId)
        fail();
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
    const task = immutableJson(options) as unknown as TaskOptions;
    if (!Array.isArray(inputs)) fail();
    const count = Object.getOwnPropertyDescriptor(inputs, "length")?.value;
    if (!Number.isSafeInteger(count) || count < 1 || count > 256) fail();
    const payloads: Readonly<ArtifactPayload>[] = [];
    // Array.map skips holes. A sparse batch must never create an unlabeled task.
    for (let index = 0; index < count; index++) {
      const entry = Object.getOwnPropertyDescriptor(inputs, index);
      if (!entry || !("value" in entry) || !entry.value || typeof entry.value !== "object") fail();
      const envelope = Object.getOwnPropertyDescriptor(entry.value, "envelope");
      const content = Object.getOwnPropertyDescriptor(entry.value, "contentBase64");
      if (!envelope || !("value" in envelope) || !content || !("value" in content)) fail();
      payloads.push(this.verifyArtifact(envelope.value, decode(content.value), task.tenantId, executor));
    }
    const sources = union(
      payloads.flatMap((p) =>
        p.sourceTaskId === null ? [] : [p.sourceTaskId],
      ),
    );
    if (sources.length > 1)
      throw new Error("Artifact imports require a single producing task");
    const sensitive = payloads.some(
      (p) =>
        p.sensitivity !== "public" ||
        p.lineageTaskIds.some((id) => executor.assertProvenance(id).sensitive),
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
    const profile = validateSandboxProfile(options.profile);
    text(options.origin);
    if (
      options.inputClassification !== undefined &&
      options.inputClassification !== "public" &&
      options.inputClassification !== "sensitive"
    )
      fail();
    const names = list(options.inputFiles).map(path);
    if (new Set(names.map((name) => name.toLowerCase())).size !== names.length)
      fail();
    const receipts = snapshot(options.inputReceipts ?? []);
    if (!Array.isArray(receipts) || receipts.length > names.length) fail();
    if (this.#buildPolicy && receipts.length !== names.length) requireAttestation();
    const receiptNames = receipts.map((receipt) => path(receipt.payload.path));
    if (
      new Set(receiptNames).size !== receiptNames.length ||
      receiptNames.some((name) => !names.includes(name))
    )
      fail();
    const root = resolve(options.workspace);
    if (
      lstatSync(root).isSymbolicLink() ||
      !lstatSync(root).isDirectory() ||
      realpathSync(root) !== root
    )
      fail();
    const staging = realpathSync(
      mkdtempSync(join(tmpdir(), "agent-guard-artifacts-")),
    );
    try {
      let remaining = profile.maxInputBytes;
      const parents: Readonly<ArtifactPayload>[] = [];
      const rawInputs: { name: string; bytes: Buffer }[] = [];
      const inputs: SignedArtifactEnvelope[] = [...receipts];
      const stagedInputs = names.map((name) => {
        const bytes = readWorkspaceInput(root, name, remaining);
        remaining -= bytes.length;
        return { name, bytes };
      });
      // Hash and copy the same private buffers. A second read of the source workspace
      // here would let a file change between approval validation and guest staging.
      (options as Partial<RegisteredSandboxOptions>)[checkStagedInputVersion]?.(
        stagedInputs.map(({ name, bytes }) => ({ path: name, sha256: hash(bytes) })),
      );
      for (const { name, bytes } of stagedInputs) {
        const receipt = receipts.find(
          (candidate) => candidate.payload.path === name,
        );
        if (receipt)
          parents.push(
            this.verifyArtifact(receipt, bytes, initial.tenantId, executor),
          );
        else rawInputs.push({ name, bytes });
        const target = join(staging, ...name.split("/"));
        mkdirSync(dirname(target), { recursive: true, mode: 0o700 });
        writeFileSync(target, bytes, { flag: "wx", mode: 0o600 });
      }
      const sensitive =
        options.inputClassification !== "public" ||
        parents.some(
          (p) =>
            p.sensitivity !== "public" ||
            p.lineageTaskIds.some(
              (id) => executor.assertProvenance(id).sensitive,
            ),
        );
      // Persist taint before any bytes or command reach the shell, including failed executions.
      this.assertOpen();
      if (sensitive) executor.markSensitive(taskId);
      const lineageTaskIds = union(executor.provenanceTaskIds(taskId));
      if (
        parents.some((p) =>
          p.lineageTaskIds.some((id) => !lineageTaskIds.includes(id)),
        )
      )
        throw new Error(
          "Import source artifacts through createTaskFromArtifacts before sandbox use",
        );
      for (const raw of rawInputs) {
        const receipt = this.#sign(
          raw.bytes,
          {
            path: raw.name,
            kind: "file",
            tenantId: initial.tenantId,
            origin: options.origin,
            sensitivity: executor.assertProvenance(taskId).sensitive
              ? "sensitive"
              : "public",
            sourceTaskId: taskId,
            lineageTaskIds,
            lineage: [],
            version: 1,
          },
          executor,
        );
        inputs.push(receipt);
        parents.push(receipt.payload);
      }
      const lineage = union(
        parents.flatMap((p) => [p.artifactId, ...p.lineage]),
      );
      const version = 1 + Math.max(0, ...parents.map((p) => p.version));
      if (version > 1_000_000) fail();
      const launch = {
        profile,
        workspace: staging,
        inputFiles: names,
        command: options.command,
        ...(options.exportFiles ? { exportFiles: options.exportFiles } : {}),
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
        sensitivity: finalSensitive
          ? ("sensitive" as const)
          : ("public" as const),
        sourceTaskId: taskId,
        lineageTaskIds,
        lineage,
      };
      const sign = (
        bytes: Buffer,
        name: string,
        kind: ArtifactPayload["kind"],
      ) => this.#sign(bytes, { ...fields, path: name, kind }, executor);
      // #sign validates locally; source checks have just succeeded and are rechecked on every import/export.
      const artifacts = result.exports.map((file) =>
        sign(decode(file.contentBase64), path(file.path), "file"),
      );
      return {
        result,
        inputs,
        artifacts,
        stdout: sign(Buffer.from(result.stdout), "stdout.txt", "stdout"),
        stderr: sign(Buffer.from(result.stderr), "stderr.txt", "stderr"),
        sensitive: finalSensitive,
      };
    } finally {
      rmSync(staging, { recursive: true, force: true });
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
    if (!Array.isArray(approved) || !approved.length || approved.length > 256)
      fail();
    const expectedTenant = output.stdout.payload.tenantId;
    const expectedSource = output.stdout.payload.sourceTaskId;
    const receipts = approved.map((selection) => {
      const receipt = output.artifacts.find(
        (item) => item.payload.path === selection.path,
      );
      const file = output.result.exports.find(
        (item) => item.path === selection.path,
      );
      if (
        !receipt ||
        !file ||
        receipt.payload.kind !== "file" ||
        selection.sha256 !== receipt.payload.sha256 ||
        receipt.payload.tenantId !== expectedTenant ||
        receipt.payload.sourceTaskId !== expectedSource
      )
        fail();
      this.verifyArtifact(
        receipt,
        decode(file.contentBase64),
        receipt.payload.tenantId,
        executor,
      );
      return receipt;
    });
    if (
      output.stdout.payload.kind !== "stdout" ||
      output.stderr.payload.kind !== "stderr" ||
      output.stderr.payload.sourceTaskId !== expectedSource
    )
      fail();
    this.verifyArtifact(
      output.stdout,
      Buffer.from(output.result.stdout),
      receipts[0]!.payload.tenantId,
      executor,
    );
    this.verifyArtifact(
      output.stderr,
      Buffer.from(output.result.stderr),
      receipts[0]!.payload.tenantId,
      executor,
    );
    const written = writeReviewedExports(output.result, approved, destination);
    try {
      writeFileSync(
        join(destination, SIDECAR),
        JSON.stringify({
          artifacts: receipts,
          stdout: output.stdout,
          stderr: output.stderr,
        }),
        { flag: "wx", mode: 0o600 },
      );
    } catch (error) {
      rmSync(destination, { recursive: true, force: true });
      throw error;
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
  profile: GovernedSandboxOptions["profile"];
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
  onResult(
    output: GovernedSandboxResult,
    context: { taskId: string },
  ): string | Promise<string>;
}
/** Register and approve this definition to place every shell invocation behind durable admission. */
export function createSandboxTool(options: SandboxToolOptions): ToolDefinition {
  const broker = options.broker;
  broker.assertOpen();
  const executor = options.executor,
    onResult = options.onResult;
  if (typeof onResult !== "function") fail();
  const config = snapshot({
    name: text(options.name),
    profile: validateSandboxProfile(options.profile),
    workspace: resolve(options.workspace),
    ...(broker.buildPolicySha256 ? { buildPolicySha256: broker.buildPolicySha256 } : {}),
    inputFiles: list(options.inputFiles).map(path),
    exportFiles: list(options.exportFiles ?? []).map(path),
    tenantId: text(options.tenantId),
    resourceId: text(options.resourceId),
    origin: text(options.origin),
    inputClassification: options.inputClassification ?? "sensitive",
    inputReceipts: [...(options.inputReceipts ?? [])],
    requiresApproval: options.requiresApproval ?? true,
  });
  if (
    !["public", "sensitive"].includes(config.inputClassification) ||
    typeof config.requiresApproval !== "boolean"
  )
    fail();
  if (config.buildPolicySha256) {
    const selected = new Set(config.inputReceipts.map((receipt) => receipt.payload.path));
    if (selected.size !== config.inputReceipts.length || selected.size !== config.inputFiles.length ||
        config.inputFiles.some((name) => !selected.has(name))) requireAttestation();
  }
  const configDigest = digestJson(config as unknown as Json);
  const versionKey = randomBytes(32);
  function parse(value: Json): Json {
    if (
      !value ||
      typeof value !== "object" ||
      Array.isArray(value) ||
      Object.keys(value).join(",") !== "command"
    )
      throw new GuardError("ARGUMENT_INVALID");
    const argv = (value as { command: Json }).command;
    if (
      !Array.isArray(argv) ||
      !argv.length ||
      argv.length > 128 ||
      argv.some(
        (arg) =>
          typeof arg !== "string" ||
          arg.includes("\0") ||
          Buffer.byteLength(arg) > 8192,
      ) ||
      Buffer.byteLength(JSON.stringify(argv)) > 128 * 1024
    )
      throw new GuardError("ARGUMENT_INVALID");
    return { command: argv };
  }
  function versionForFiles(files: FileDigest[]): string {
    return `hmac-sha256:${createHmac("sha256", versionKey).update(canonicalJson({ configDigest, files })).digest("hex")}`;
  }
  function resourceVersion(): string {
    broker.assertOpen();
    if (
      lstatSync(config.workspace).isSymbolicLink() ||
      !lstatSync(config.workspace).isDirectory() ||
      realpathSync(config.workspace) !== config.workspace
    )
      fail();
    let remaining = config.profile.maxInputBytes;
    const files = config.inputFiles.map((name) => {
      const bytes = readWorkspaceInput(config.workspace, name, remaining);
      remaining -= bytes.length;
      if (config.buildPolicySha256) {
        const receipt = config.inputReceipts.find((item) => item.payload.path === name);
        if (!receipt) requireAttestation();
        broker.verifyArtifact(receipt, bytes, config.tenantId, executor);
      }
      return { path: name, sha256: hash(bytes) };
    });
    return versionForFiles(files);
  }
  const logs = (value: string, receipt: SignedArtifactEnvelope): Json => {
    const bytes = Buffer.from(value);
    return {
      text: bytes.subarray(0, 16 * 1024).toString("utf8"),
      truncated: bytes.length > 16 * 1024,
      artifactId: receipt.payload.artifactId,
      sha256: receipt.payload.sha256,
      sensitivity: receipt.payload.sensitivity,
    };
  };
  return {
    name: config.name,
    description:
      "Run approved command arguments in a bounded Linux container; retain signed output with the host.",
    inputSchema: {
      type: "object",
      properties: {
        command: {
          type: "array",
          items: { type: "string", maxLength: 8192 },
          minItems: 1,
          maxItems: 128,
        },
      },
      required: ["command"],
      additionalProperties: false,
    },
    metadata: {
      adapter: "governed-docker-sandbox-v1",
      configurationDigest: configDigest,
      image: config.profile.image,
    },
    requiresApproval: config.requiresApproval,
    parse,
    resolve: (args, task) => {
      parse(args);
      if (task.tenantId !== config.tenantId)
        throw new GuardError("TENANT_DENIED");
      return {
        resourceId: config.resourceId,
        tenantId: config.tenantId,
        resourceVersion: resourceVersion(),
        sensitive:
          config.inputClassification !== "public" ||
          config.inputReceipts.some(
            (receipt) => receipt.payload.sensitivity !== "public",
          ),
      };
    },
    execute: async (args, context) => {
      const parsed = parse(args) as { command: string[] };
      if (
        context.task.tenantId !== config.tenantId ||
        context.action.resourceId !== config.resourceId
      )
        throw new GuardError("TOOL_CHANGED");
      if (context.signal.aborted) throw new GuardError("EXECUTION_ABORTED");
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
          if (versionForFiles(files) !== context.action.resourceVersion)
            throw new GuardError("TOOL_CHANGED");
        },
      };
      const output = await broker.runGovernedSandbox(executor, context.task.id, launch);
      if (context.signal.aborted) throw new GuardError("EXECUTION_ABORTED");
      const resultId = text(
        await onResult(output, { taskId: context.task.id }),
      );
      return {
        value: {
          resultId,
          exitCode: output.result.exitCode,
          sensitive: output.sensitive,
          stdout: logs(output.result.stdout, output.stdout),
          stderr: logs(output.result.stderr, output.stderr),
          artifactIds: output.artifacts.map(
            (receipt) => receipt.payload.artifactId,
          ),
        },
      };
    },
  };
}
