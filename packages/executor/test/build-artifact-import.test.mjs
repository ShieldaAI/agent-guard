import test from "node:test";
import assert from "node:assert/strict";
import { createHash, generateKeyPairSync, randomBytes, sign } from "node:crypto";
import { mkdtempSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ArtifactBroker, createSandboxTool, DurableExecutor } from "../dist/index.js";

const sha256 = (bytes) => createHash("sha256").update(bytes).digest("hex");
const input = (envelope, bytes) => ({ envelope, contentBase64: bytes.toString("base64") });
const task = (id, tenantId = "engineering") => ({
  id, tenantId, principalId: "pilot-operator", grants: [{ tool: "shell", resources: ["workspace"] }],
  budget: { maxCalls: 3, maxConcurrent: 1, maxCost: 0, deadline: Date.now() + 60_000 },
});

// Core intentionally masks resolver exceptions. Observe only the fixed Windows
// helper labels in this test process; never retry or expose the original error.
function diagnoseWorkspaceResolver(resolve, diagnostic) {
  return function (...args) {
    try { return Reflect.apply(resolve, this, args); }
    catch (error) {
      try {
        const own = name => Object.getOwnPropertyDescriptor(error, name)?.value;
        const code = own("code"), reason = own("reason"), stage = own("stage");
        if (code === "WORKSPACE_INPUT_UNAVAILABLE" &&
            ["selection", "startup", "timeout", "spawn", "exit", "protocol", "cleanup"].includes(reason) &&
            ["not-started", "compiling", "copying", "complete"].includes(stage)) {
          diagnostic(JSON.stringify({ code, reason, stage }));
        }
      } catch { /* A diagnostic must not replace the exact resolver exception. */ }
      throw error;
    }
  };
}

test("test-only workspace diagnostics preserve resolver calls and retain only fixed error labels", () => {
  const receiver = {}, argument = {}, result = {}, recorded = [];
  let calls = 0;
  const wrapped = diagnoseWorkspaceResolver(function (...args) {
    calls++; assert.equal(this, receiver); assert.equal(args.length, 1); assert.equal(args[0], argument); return result;
  }, value => recorded.push(value));
  assert.equal(Reflect.apply(wrapped, receiver, [argument]), result); assert.equal(calls, 1); assert.deepEqual(recorded, []);
  const failure = Object.assign(new Error("private selected content and path"),
    { code: "WORKSPACE_INPUT_UNAVAILABLE", reason: "timeout", stage: "compiling" });
  const rejecting = diagnoseWorkspaceResolver(() => { calls++; throw failure; }, value => recorded.push(value));
  assert.throws(rejecting, error => error === failure); assert.equal(calls, 2);
  assert.deepEqual(recorded, ['{"code":"WORKSPACE_INPUT_UNAVAILABLE","reason":"timeout","stage":"compiling"}']);
  failure.stage = "private unexpected stage";
  assert.throws(rejecting, error => error === failure); assert.equal(recorded.length, 1);
  failure.stage = "copying";
  assert.throws(diagnoseWorkspaceResolver(() => { throw failure; }, () => { throw new Error("diagnostic failed"); }), error => error === failure);
});

function build(t) {
  const bytes = Buffer.from("attested fixture bytes");
  const pair = generateKeyPairSync("ed25519");
  const signer = sha256(pair.publicKey.export({ type: "spki", format: "der" }));
  const rule = {
    tenantId: "engineering", path: "input.txt", sha256: sha256(bytes),
    subjectName: "reports-package", builderId: "https://builder.example/pipeline",
    buildType: "https://builder.example/build/package/v1", sourceUri: "git+https://source.example/reports",
    sourceDigest: { algorithm: "sha256", value: sha256("fixture source revision") },
    signerPublicKeyPem: pair.publicKey.export({ type: "spki", format: "pem" }),
  };
  const hostKey = randomBytes(32);
  const brokerFor = (enrollment) => {
    const broker = new ArtifactBroker({ key: hostKey, keyId: "host-receipts",
      ...(enrollment ? { buildPolicy: { artifacts: [enrollment] } } : {}) });
    t.after(() => broker.close());
    return broker;
  };
  const broker = brokerFor(rule);
  const executor = new DurableExecutor({ database: ":memory:", encryptionKey: randomBytes(32) });
  t.after(() => executor.close());
  const payloadType = "application/vnd.in-toto+json";
  const payload = Buffer.from(JSON.stringify({
    _type: "https://in-toto.io/Statement/v1", predicateType: "https://slsa.dev/provenance/v1",
    subject: [{ name: rule.subjectName, digest: { sha256: rule.sha256 } }],
    predicate: {
      buildDefinition: { buildType: rule.buildType, externalParameters: {},
        resolvedDependencies: [{ uri: rule.sourceUri, digest: { sha256: rule.sourceDigest.value } }] },
      runDetails: { builder: { id: rule.builderId } },
    },
  }));
  const pae = Buffer.concat([Buffer.from(`DSSEv1 ${Buffer.byteLength(payloadType)} ${payloadType} ${payload.length} `), payload]);
  const attestation = { payloadType, payload: payload.toString("base64"),
    signatures: [{ keyid: signer, sig: sign(null, pae, pair.privateKey).toString("base64") }] };
  const admission = { path: rule.path, tenantId: rule.tenantId, content: bytes, attestation };
  return { broker, brokerFor, executor, rule, bytes, admission, payload, signer };
}

function absent(executor, id) {
  assert.throws(() => executor.snapshot(id), { code: "INVALID_TASK" });
}

test("externally signed build roots bind actual bytes, tenant and enrolled policy to task imports", (t) => {
  const { broker, brokerFor, executor, rule, bytes, admission, payload, signer } = build(t);
  const root = broker.admitBuildArtifact(admission);
  assert.equal(root.payload.schemaVersion, 2);
  assert.equal(root.payload.trust, "untrusted");
  assert.equal(root.payload.sensitivity, "sensitive");
  assert.equal(root.payload.buildProvenance.statementSha256, sha256(payload));
  assert.equal(root.payload.buildProvenance.signerSha256, signer);
  assert.equal(root.payload.buildProvenance.policySha256, root.payload.buildPolicySha256);
  const serialized = JSON.stringify(root);
  for (const privateDetail of [rule.builderId, rule.sourceUri, rule.sourceDigest.value, rule.signerPublicKeyPem, admission.attestation.payload]) {
    assert.equal(serialized.includes(privateDetail), false);
  }
  const reopened = brokerFor(structuredClone(rule));
  const imported = reopened.createTaskFromArtifacts(executor, task("approved"), [input(root, bytes)]);
  assert.equal(executor.snapshot(imported.taskId).sensitive, true);
  // Caller-controlled input traversal cannot switch the already-enrolled task identity.
  const requested = task("pinned-task");
  const changingInputs = new Proxy([input(root, bytes)], {
    getOwnPropertyDescriptor(target, key) {
      requested.id = "redirected-task";
      requested.tenantId = "foreign";
      return Reflect.getOwnPropertyDescriptor(target, key);
    },
  });
  broker.createTaskFromArtifacts(executor, requested, changingInputs);
  assert.equal(executor.snapshot("pinned-task").sensitive, true);
  absent(executor, "redirected-task");
  for (const patch of [{ content: Buffer.from("replaced") }, { tenantId: "foreign" }, { path: "other.txt" }]) {
    assert.throws(() => broker.admitBuildArtifact({ ...admission, ...patch }));
  }
  const tampered = structuredClone(root);
  tampered.payload.buildProvenance.statementSha256 = "0".repeat(64);
  for (const [name, items, tenant] of [
    ["changed-receipt", [input(tampered, bytes)]],
    ["changed-content", [input(root, Buffer.from("other bytes"))]],
    ["mixed-import", [input(root, bytes), input(tampered, bytes)]],
    ["foreign", [input(root, bytes)], "foreign"],
    ["empty-slot", new Array(1)],
  ]) {
    assert.throws(() => broker.createTaskFromArtifacts(executor, task(name, tenant), items));
    absent(executor, name);
  }
  const legacy = brokerFor();
  assert.throws(() => broker.classifyArtifact({ ...admission, origin: "operator" }), { code: "ARTIFACT_ATTESTATION_REQUIRED" });
  const raw = legacy.classifyArtifact({ ...admission, origin: "verified-build" });
  assert.equal(raw.payload.schemaVersion, 1);
  assert.throws(() => broker.verifyArtifact(raw, bytes, rule.tenantId));
  assert.throws(() => legacy.verifyArtifact(root, bytes, rule.tenantId));
  assert.throws(() => legacy.admitBuildArtifact(admission), { code: "ARTIFACT_ATTESTATION_REQUIRED" });
  const rotated = brokerFor({ ...rule, builderId: "https://builder.example/next" });
  assert.throws(() => rotated.createTaskFromArtifacts(executor, task("old-policy"), [input(root, bytes)]));
  absent(executor, "old-policy");
});

test("strict governed tools reject omitted receipts and content replacement before dispatch", async (t) => {
  const { broker, executor, bytes, rule, admission } = build(t);
  const workspace = realpathSync(mkdtempSync(join(tmpdir(), "guard-build-input-")));
  t.after(() => rmSync(workspace, { recursive: true, force: true }));
  writeFileSync(join(workspace, rule.path), bytes);
  const receipt = broker.admitBuildArtifact(admission);
  broker.createTaskFromArtifacts(executor, task("scoped"), [input(receipt, bytes)]);
  let outputs = 0;
  const toolOptions = { executor, broker, name: "shell", resourceId: "workspace", tenantId: rule.tenantId,
    origin: "approved-shell", profile: { image: `alpine@sha256:${"a".repeat(64)}` },
    workspace, inputFiles: [rule.path], inputClassification: "public", onResult() { outputs++; return "result"; } };
  assert.throws(() => createSandboxTool(toolOptions), { code: "ARTIFACT_ATTESTATION_REQUIRED" });
  await assert.rejects(broker.runGovernedSandbox(executor, "scoped", {
    ...toolOptions, command: ["/bin/true"],
  }), { code: "ARTIFACT_ATTESTATION_REQUIRED" });
  const definition = createSandboxTool({ ...toolOptions, inputReceipts: [receipt] });
  definition.resolve = diagnoseWorkspaceResolver(definition.resolve, value => t.diagnostic(value));
  executor.approveTool("shell", executor.registerTool(definition));
  const prepared = await executor.prepare("scoped", { tool: "shell", args: { command: ["/bin/true"] } });
  const approvalId = executor.approve(prepared.id, { approverId: "operator", expiresAt: Date.now() + 30_000 });
  writeFileSync(join(workspace, rule.path), "replacement");
  await assert.rejects(executor.execute("scoped", prepared.id, { approvalId }), { code: "TOOL_CHANGED" });
  assert.equal(executor.execution("scoped", prepared.id).status, "UNKNOWN");
  assert.equal(executor.snapshot("scoped").calls, 1);
  assert.equal(outputs, 0);
});

const image = process.env.AGENT_GUARD_SANDBOX_IMAGE;
test("closing a broker blocks zero-input sandbox preparation and approved launches before workspace access", async (t) => {
  const { broker: strict, brokerFor, executor } = build(t);
  for (const [id, broker] of [["strict", strict], ["legacy", brokerFor()]]) {
    const workspace = realpathSync(mkdtempSync(join(tmpdir(), "guard-closed-broker-")));
    t.after(() => rmSync(workspace, { recursive: true, force: true }));
    let outputs = 0;
    const options = { executor, broker, name: "shell", resourceId: "workspace", tenantId: "engineering",
      origin: "host:rotation", profile: { image: `alpine@sha256:${"a".repeat(64)}` }, workspace,
      inputFiles: [], inputClassification: "public", onResult() { outputs++; return "result"; } };
    const tool = createSandboxTool(options);
    executor.approveTool("shell", executor.registerTool(tool));
    executor.createTask(task(id));
    const request = { tool: "shell", args: { command: ["/bin/true"] } };
    const prepared = await executor.prepare(id, request);
    const approvalId = executor.approve(prepared.id, { approverId: "operator", expiresAt: Date.now() + 30_000 });
    broker.close();
    rmSync(workspace, { recursive: true });
    const closed = { code: "ARTIFACT_BROKER_CLOSED" };
    assert.throws(() => createSandboxTool(options), closed);
    for (const files of [[], ["missing.txt"]]) {
      await assert.rejects(broker.runGovernedSandbox(executor, id, {
        ...options, inputClassification: "sensitive", inputFiles: files, command: request.args.command,
      }), closed);
    }
    assert.equal(executor.snapshot(id).sensitive, false);
    await assert.rejects(executor.prepare(id, request));
    await assert.rejects(executor.execute(id, prepared.id, { approvalId }), closed);
    assert.equal(executor.execution(id, prepared.id).status, "UNKNOWN");
    assert.equal(outputs, 0);
  }
});

test("real governed sandbox imports an attested build and rejects derivatives after policy rotation", { skip: !image }, async (t) => {
  const { broker, brokerFor, executor, rule, bytes, admission } = build(t);
  const workspace = realpathSync(mkdtempSync(join(tmpdir(), "guard-build-sandbox-")));
  t.after(() => rmSync(workspace, { recursive: true, force: true }));
  writeFileSync(join(workspace, rule.path), bytes);
  const root = broker.admitBuildArtifact(admission);
  broker.createTaskFromArtifacts(executor, task("build"), [input(root, bytes)]);
  let result;
  const tool = createSandboxTool({ name: "shell", executor, broker, profile: { image }, tenantId: rule.tenantId,
    resourceId: "workspace", origin: "host:build-pilot", workspace, inputFiles: [rule.path], inputReceipts: [root],
    exportFiles: ["derived.txt"], inputClassification: "public", onResult(value) { result = value; return "completed"; } });
  executor.approveTool("shell", executor.registerTool(tool));
  const prepared = await executor.prepare("build", { tool: "shell", args: { command: ["/bin/sh", "-c", "cat input.txt > derived.txt; cat derived.txt"] } });
  await assert.rejects(executor.execute("build", prepared.id), { code: "APPROVAL_REQUIRED" });
  assert.equal(result, undefined);
  const approvalId = executor.approve(prepared.id, { approverId: "operator", expiresAt: Date.now() + 30_000 });
  await executor.execute("build", prepared.id, { approvalId });
  assert.equal(result.result.exitCode, 0);
  assert.equal(result.result.stdout, bytes.toString());
  const derived = result.artifacts[0];
  assert(derived.payload.lineage.includes(root.payload.artifactId));
  for (const output of [derived, result.stdout, result.stderr]) {
    assert.equal(output.payload.schemaVersion, 2);
    assert.equal(output.payload.buildPolicySha256, root.payload.buildPolicySha256);
    assert.equal(output.payload.buildProvenance, undefined);
    assert.equal(output.payload.sensitivity, "sensitive");
  }
  broker.createTaskFromArtifacts(executor, task("derived-import"), [input(derived, bytes)]);
  assert(executor.snapshot("derived-import").sensitive);
  const rotated = brokerFor({ ...rule, signerPublicKeyPem: generateKeyPairSync("ed25519").publicKey.export({ type: "spki", format: "pem" }) });
  assert.throws(() => rotated.createTaskFromArtifacts(executor, task("rotated-import"), [input(derived, bytes)]));
  absent(executor, "rotated-import");
  // The same host key signed this genuine legacy output, but it used the unprotected policy.
  const legacy = brokerFor();
  const raw = await legacy.runGovernedSandbox(executor, "build", {
    profile: { image }, workspace, origin: "legacy", inputFiles: [rule.path], command: ["/bin/cat", rule.path],
  });
  assert.equal(raw.stdout.payload.schemaVersion, 1);
  assert.throws(() => broker.createTaskFromArtifacts(executor, task("legacy-derived"), [input(raw.stdout, bytes)]));
  absent(executor, "legacy-derived");
});
