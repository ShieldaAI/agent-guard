import test from "node:test";
import assert from "node:assert/strict";
import { createHash, randomBytes } from "node:crypto";
import {
  mkdtempSync,
  writeFileSync,
  readFileSync,
  rmSync,
  chmodSync,
  realpathSync,
  symlinkSync,
  linkSync,
  mkdirSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createServer } from "node:http";
import { DurableExecutor } from "../dist/executor.js";
import {
  createPrivateFileTools,
  createHttpGetTool,
  createOutboundJsonTool,
  publicToolDefinition,
} from "../dist/adapters.js";

function directory(t) {
  const dir = realpathSync(
    mkdtempSync(join(tmpdir(), "agent-guard-adapters-")),
  );
  chmodSync(dir, 0o700);
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  return dir;
}
function executor(t, tools, resources, recipients = []) {
  const host = new DurableExecutor({
    database: ":memory:",
    encryptionKey: randomBytes(32),
  });
  t.after(() => host.close());
  for (const tool of tools)
    host.approveTool(tool.name, host.registerTool(tool));
  const credential = host.createTask({
    id: randomBytes(8).toString("hex"),
    principalId: "human",
    tenantId: "tenant",
    grants: tools.map((tool) => ({ tool: tool.name, resources })),
    allowedRecipients: recipients,
    budget: {
      maxCalls: 20,
      maxConcurrent: 2,
      maxCost: 0,
      deadline: Date.now() + 60_000,
    },
  });
  return { host, taskId: credential.taskId };
}
async function execute(host, taskId, tool, args) {
  const prepared = await host.prepare(taskId, { tool: tool.name, args });
  const approvalId = prepared.requiresApproval
    ? host.approve(prepared.id, {
        approverId: "operator",
        expiresAt: Date.now() + 30_000,
      })
    : undefined;
  return host.execute(taskId, prepared.id, approvalId ? { approvalId } : {});
}
async function server(t, callback) {
  const instance = createServer(callback);
  await new Promise((resolve) => instance.listen(0, "127.0.0.1", resolve));
  t.after(
    () =>
      new Promise((resolve) => {
        instance.close(resolve);
        instance.closeAllConnections();
      }),
  );
  return `http://127.0.0.1:${instance.address().port}`;
}
const network = (origin) => ({
  allowedOrigins: [origin],
  allowPrivateOrigins: [origin],
  maxRequestBytes: 2048,
  maxResponseBytes: 2048,
  timeoutMs: 2000,
});

test("file tools bind opaque versions, enforce grants and atomically write only private files", async (t) => {
  const dir = directory(t);
  writeFileSync(join(dir, "input.txt"), "original", { mode: 0o600 });
  const tools = createPrivateFileTools({
    directory: dir,
    tenantId: "tenant",
    resourcePrefix: "files",
    sensitiveReads: false,
  });
  const { host, taskId } = executor(t, Object.values(tools), [
    "files/input.txt",
    "files/nested/output.txt",
  ]);
  const read = await execute(host, taskId, tools.read, { path: "input.txt" });
  assert.equal(read.content, "original");
  assert.match(read.version, /^sha256:[a-f0-9]{64}$/);
  const write = await execute(host, taskId, tools.write, {
    path: "nested/output.txt",
    content: "approved",
  });
  assert.match(write.version, /^sha256:/);
  assert.equal(
    readFileSync(join(dir, "nested/output.txt"), "utf8"),
    "approved",
  );
  await assert.rejects(
    host.prepare(taskId, {
      tool: tools.write.name,
      args: { path: "forbidden.txt", content: "denied" },
    }),
    /GRANT_DENIED/,
  );
  const prepared = await host.prepare(taskId, {
    tool: tools.write.name,
    args: { path: "input.txt", content: "new" },
  });
  const approvalId = host.approve(prepared.id, {
    approverId: "operator",
    expiresAt: Date.now() + 30_000,
  });
  writeFileSync(join(dir, "input.txt"), "changed after approval");
  await assert.rejects(
    host.execute(taskId, prepared.id, { approvalId }),
    /ADAPTER_BINDING_CHANGED/,
  );
  assert.equal(
    readFileSync(join(dir, "input.txt"), "utf8"),
    "changed after approval",
  );
});

test("private file path aliases, symlinks, hardlinks, unsafe permissions, oversized bytes and post-prepare changes are rejected", async (t) => {
  const dir = directory(t);
  writeFileSync(join(dir, "Case.txt"), "value", { mode: 0o600 });
  const tools = createPrivateFileTools({
    directory: dir,
    tenantId: "tenant",
    resourcePrefix: "files",
    maxBytes: 8,
  });
  for (const path of [
    "../escape",
    "/etc/passwd",
    "C:/escape",
    "a\\b",
    "./Case.txt",
    "Case.txt ",
    "a//b",
    "NUL",
    "e\u0301.txt",
  ])
    assert.throws(() => tools.read.parse({ path }));
  const identity = { id: "task", tenantId: "tenant", principalId: "human" };
  assert.throws(
    () => tools.read.resolve({ path: "case.txt" }, identity),
    /ALIAS/,
  );
  assert.throws(
    () => tools.write.parse({ path: "safe.txt", content: "too many bytes" }),
    /SIZE/,
  );
  symlinkSync(join(dir, "Case.txt"), join(dir, "link.txt"));
  assert.throws(
    () => tools.read.resolve({ path: "link.txt" }, identity),
    /UNSAFE/,
  );
  linkSync(join(dir, "Case.txt"), join(dir, "hard.txt"));
  assert.throws(
    () => tools.read.resolve({ path: "hard.txt" }, identity),
    /UNSAFE/,
  );
  if (process.platform !== "win32") {
    const unsafe = join(dir, "unsafe");
    mkdirSync(unsafe, { mode: 0o755 });
    assert.throws(
      () =>
        createPrivateFileTools({
          directory: unsafe,
          tenantId: "tenant",
          resourcePrefix: "files",
        }),
      /UNSAFE/,
    );
  }
});

test("prepared reads cannot return bytes that changed after authorization", async (t) => {
  const dir = directory(t);
  writeFileSync(join(dir, "input.txt"), "approved bytes", { mode: 0o600 });
  const tools = createPrivateFileTools({
    directory: dir,
    tenantId: "tenant",
    resourcePrefix: "files",
  });
  const { host, taskId } = executor(t, [tools.read], ["files/input.txt"]);
  const prepared = await host.prepare(taskId, {
    tool: tools.read.name,
    args: { path: "input.txt" },
  });
  writeFileSync(join(dir, "input.txt"), "different bytes");
  await assert.rejects(
    host.execute(taskId, prepared.id),
    /ADAPTER_BINDING_CHANGED/,
  );
});

test("HTTP GET only uses a host resource alias and enforces actual ETag even if the server ignores If-Match", async (t) => {
  let requests = 0,
    revision = '"v1"';
  const origin = await server(t, (req, res) => {
    requests++;
    assert.equal(req.method, "GET");
    assert.equal(req.url, "/document");
    assert.equal(req.headers["if-match"], '"v1"');
    res.writeHead(200, { "content-type": "application/json", etag: revision });
    res.end(JSON.stringify({ value: "document" }));
  });
  const tool = createHttpGetTool({
    name: "http.read",
    tenantId: "tenant",
    resourcePrefix: "http",
    resources: { document: { url: `${origin}/document`, etag: '"v1"' } },
    network: network(origin),
  });
  const { host, taskId } = executor(
    t,
    [tool],
    ["http/document"],
    [`${origin}/document`],
  );
  const prepared = await host.prepare(taskId, {
    tool: tool.name,
    args: { resource: "document" },
  });
  assert.equal(requests, 0);
  assert.equal(
    (await host.execute(taskId, prepared.id)).body.value,
    "document",
  );
  revision = '"v2"';
  await assert.rejects(
    execute(host, taskId, tool, { resource: "document" }),
    /VERSION_OR_STATUS/,
  );
  await assert.rejects(
    host.prepare(taskId, {
      tool: tool.name,
      args: { resource: "document", url: "https://attacker.example/" },
    }),
    /ARGUMENT_INVALID/,
  );
  assert.equal(requests, 2);
});

test("HTTP GET rejects redirects without contacting the redirected endpoint", async (t) => {
  let redirected = false;
  const origin = await server(t, (req, res) => {
    if (req.url === "/redirect") {
      res.writeHead(302, { location: `${origin}/capture` });
      res.end();
    } else {
      redirected = true;
      res.end("bad");
    }
  });
  const tool = createHttpGetTool({
    name: "http.read",
    tenantId: "tenant",
    resourcePrefix: "http",
    resources: { document: { url: `${origin}/redirect` } },
    network: network(origin),
  });
  const { host, taskId } = executor(
    t,
    [tool],
    ["http/document"],
    [`${origin}/redirect`],
  );
  await assert.rejects(
    execute(host, taskId, tool, { resource: "document" }),
    /REDIRECT_DENIED/,
  );
  assert.equal(redirected, false);
});

function payload(value) {
  if (
    !value ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    Object.keys(value).join(",") !== "message" ||
    typeof value.message !== "string"
  )
    throw new Error("invalid");
  return { message: value.message.trim() };
}
function outbound(origin, credential) {
  return createOutboundJsonTool({
    name: "message.send",
    tenantId: "tenant",
    resourcePrefix: "messages",
    resource: "review-room",
    recipient: "room:review",
    endpoint: `${origin}/send`,
    credentialVersion: "v1",
    credential,
    parsePayload: payload,
    payloadSchema: {
      type: "object",
      properties: { message: { type: "string" } },
      required: ["message"],
      additionalProperties: false,
    },
    network: network(origin),
  });
}

test("outbound JSON fixes endpoint/recipient, reads host credentials only after approval and never exposes them in public metadata", async (t) => {
  let calls = 0,
    credentialCalls = 0,
    received;
  const origin = await server(t, async (req, res) => {
    calls++;
    assert.equal(req.url, "/send");
    assert.equal(req.method, "POST");
    assert.equal(req.headers.authorization, "Bearer host-only-token");
    const chunks = [];
    for await (const chunk of req) chunks.push(chunk);
    received = JSON.parse(Buffer.concat(chunks).toString());
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify({ reflected: req.headers.authorization }));
  });
  const tool = outbound(origin, () => {
    credentialCalls++;
    return { value: "host-only-token", version: "v1" };
  });
  const { host, taskId } = executor(
    t,
    [tool],
    ["messages/review-room"],
    ["room:review"],
  );
  const prepared = await host.prepare(taskId, {
    tool: tool.name,
    args: { payload: { message: " hello " } },
  });
  assert.equal(credentialCalls, 0);
  await assert.rejects(host.execute(taskId, prepared.id), /APPROVAL_REQUIRED/);
  assert.equal(calls, 0);
  const approvalId = host.approve(prepared.id, {
    approverId: "operator",
    expiresAt: Date.now() + 30_000,
  });
  const result = await host.execute(taskId, prepared.id, { approvalId });
  assert.deepEqual(received, {
    recipient: "room:review",
    payload: { message: "hello" },
  });
  assert.equal(credentialCalls, 1);
  assert.equal(result.accepted, true);
  assert.equal(JSON.stringify(result).includes("host-only-token"), false);
  assert.equal(
    JSON.stringify(publicToolDefinition(tool)).includes("host-only-token"),
    false,
  );
  assert.equal("execute" in publicToolDefinition(tool), false);
  for (const extra of ["endpoint", "recipient", "credential", "tenantId"])
    await assert.rejects(
      host.prepare(taskId, {
        tool: tool.name,
        args: { payload: { message: "x" }, [extra]: "attacker" },
      }),
      /ARGUMENT_INVALID/,
    );
});

test("credential rotation and recipient denial prevent outbound requests; failed writes are not automatically retried", async (t) => {
  let requests = 0,
    version = "v1";
  const origin = await server(t, (req, res) => {
    requests++;
    req.resume();
    res.writeHead(503);
    res.end("unavailable");
  });
  const tool = outbound(origin, () => ({ value: "host-token", version }));
  const { host, taskId } = executor(
    t,
    [tool],
    ["messages/review-room"],
    ["room:review"],
  );
  const prepared = await host.prepare(taskId, {
    tool: tool.name,
    args: { payload: { message: "hello" } },
  });
  const approvalId = host.approve(prepared.id, {
    approverId: "operator",
    expiresAt: Date.now() + 30_000,
  });
  version = "v2";
  await assert.rejects(
    host.execute(taskId, prepared.id, { approvalId }),
    /CREDENTIAL_CHANGED/,
  );
  assert.equal(requests, 0);
  version = "v1";
  await assert.rejects(
    execute(host, taskId, tool, { payload: { message: "hello" } }),
    /HTTP_STATUS/,
  );
  assert.equal(requests, 1);
  const denied = executor(t, [tool], ["messages/review-room"], []);
  await assert.rejects(
    denied.host.prepare(denied.taskId, {
      tool: tool.name,
      args: { payload: { message: "x" } },
    }),
    /RECIPIENT_DENIED/,
  );
  assert.equal(requests, 1);
});

test("outbound payload transformation runs exactly once and approval binds the normalized result", async (t) => {
  let transforms = 0,
    received;
  const origin = await server(t, async (req, res) => {
    const chunks = [];
    for await (const chunk of req) chunks.push(chunk);
    received = JSON.parse(Buffer.concat(chunks).toString());
    res.writeHead(204);
    res.end();
  });
  const tool = createOutboundJsonTool({
    name: "normalize.send",
    tenantId: "tenant",
    resourcePrefix: "messages",
    resource: "room",
    recipient: "room:review",
    endpoint: `${origin}/send`,
    credentialVersion: "v1",
    credential: () => ({ value: "host-token", version: "v1" }),
    parsePayload: (value) => ({
      message: value.message.trim(),
      normalization: ++transforms,
    }),
    payloadSchema: {
      type: "object",
      properties: { message: { type: "string" } },
      required: ["message"],
      additionalProperties: false,
    },
    network: network(origin),
  });
  const { host, taskId } = executor(
    t,
    [tool],
    ["messages/room"],
    ["room:review"],
  );
  const prepared = await host.prepare(taskId, {
    tool: tool.name,
    args: { payload: { message: " normalized once " } },
  });
  assert.equal(transforms, 1);
  assert.deepEqual(JSON.parse(JSON.stringify(prepared.action.args)), {
    payload: { message: "normalized once", normalization: 1 },
  });
  const approvalId = host.approve(prepared.id, {
    approverId: "operator",
    expiresAt: Date.now() + 30_000,
  });
  await host.execute(taskId, prepared.id, { approvalId });
  assert.equal(transforms, 1);
  assert.deepEqual(received, {
    recipient: "room:review",
    payload: { message: "normalized once", normalization: 1 },
  });
});

test("preparation exposes opaque per-instance file versions before approved sensitive reads", async (t) => {
  const dir = directory(t);
  writeFileSync(join(dir, "secret.txt"), "yes", { mode: 0o600 });
  const config = {
    directory: dir,
    tenantId: "tenant",
    resourcePrefix: "files",
  };
  const tools = createPrivateFileTools(config);
  tools.read.requiresApproval = true;
  const { host, taskId } = executor(t, [tools.read], ["files/secret.txt"]);
  const prepared = await host.prepare(taskId, {
    tool: tools.read.name,
    args: { path: "secret.txt" },
  });
  assert.match(prepared.action.resourceVersion, /^hmac-sha256:[a-f0-9]{64}$/);
  assert.notEqual(
    prepared.action.resourceVersion.split(":")[1],
    createHash("sha256").update("yes").digest("hex"),
  );
  const second = createPrivateFileTools(config).read.resolve(
    { path: "secret.txt" },
    { tenantId: "tenant" },
  );
  assert.notEqual(prepared.action.resourceVersion, second.resourceVersion);
  assert.equal(host.snapshot(taskId).sensitive, false);
  await assert.rejects(
    host.execute(taskId, prepared.id),
    (error) => error.code === "APPROVAL_REQUIRED",
  );
  const approvalId = host.approve(prepared.id, {
    approverId: "operator",
    expiresAt: Date.now() + 30_000,
  });
  const result = await host.execute(taskId, prepared.id, { approvalId });
  assert.equal(result.content, "yes");
  assert.equal(
    result.version,
    `sha256:${createHash("sha256").update("yes").digest("hex")}`,
  );
  assert.equal(host.snapshot(taskId).sensitive, true);
});
