import test from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import {
  mkdtempSync,
  realpathSync,
  rmSync,
  writeFileSync,
  readFileSync,
  existsSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DurableExecutor } from "../dist/executor.js";
import {
  ArtifactBroker,
  createSandboxTool,
  runGovernedSandbox,
} from "../dist/artifacts.js";

function setup(t) {
  const directory = realpathSync(
    mkdtempSync(join(tmpdir(), "agent-guard-artifact-test-")),
  );
  const host = new DurableExecutor({
    database: ":memory:",
    encryptionKey: randomBytes(32),
  });
  const key = randomBytes(32);
  const broker = new ArtifactBroker({ key, keyId: "host-key-1" });
  t.after(() => {
    broker.close();
    host.close();
    rmSync(directory, { recursive: true, force: true });
  });
  return { directory, host, key, broker };
}
function options(id, tenantId = "tenant") {
  return {
    id,
    tenantId,
    principalId: "operator",
    grants: [{ tool: "send", resources: ["outbox"] }],
    allowedRecipients: ["receiver"],
    budget: {
      maxCalls: 10,
      maxConcurrent: 2,
      maxCost: 0,
      deadline: Date.now() + 120_000,
    },
  };
}
const input = (envelope, bytes) => ({
  envelope,
  contentBase64: Buffer.from(bytes).toString("base64"),
});
const copy = (value) => JSON.parse(JSON.stringify(value));
function assertNoTask(host, id) {
  assert.throws(
    () => host.snapshot(id),
    (error) => error.code === "INVALID_TASK",
  );
}

test("artifact receipts default to sensitive and bind bytes, tenant, labels, origin, lineage and version", (t) => {
  const { host, broker, key } = setup(t);
  const bytes = Buffer.from("confidential");
  const receipt = broker.classifyArtifact({
    content: bytes,
    path: "data.txt",
    tenantId: "tenant",
    origin: "operator:upload",
  });
  assert.equal(receipt.payload.sensitivity, "sensitive");
  assert.equal(receipt.payload.trust, "untrusted");
  assert.equal(
    broker.verifyArtifact(receipt, bytes, "tenant").bytes,
    bytes.length,
  );
  const reopened = new ArtifactBroker({ key, keyId: "host-key-1" });
  t.after(() => reopened.close());
  assert.equal(
    reopened.verifyArtifact(receipt, bytes, "tenant").artifactId,
    receipt.payload.artifactId,
  );
  const mutations = [
    (p) => {
      p.sensitivity = "public";
    },
    (p) => {
      p.tenantId = "other";
    },
    (p) => {
      p.origin = "trusted";
    },
    (p) => {
      p.version++;
    },
    (p) => {
      p.lineage = ["forged"];
    },
    (p) => {
      p.bytes++;
    },
    (p) => {
      p.extra = "surprise";
    },
  ];
  for (const [index, mutate] of mutations.entries()) {
    const changed = copy(receipt);
    mutate(changed.payload);
    assert.throws(() =>
      broker.createTaskFromArtifacts(host, options(`forged-${index}`), [
        input(changed, bytes),
      ]),
    );
    assertNoTask(host, `forged-${index}`);
  }
  assert.throws(() =>
    broker.createTaskFromArtifacts(host, options("wrong-bytes"), [
      input(receipt, "different"),
    ]),
  );
  assertNoTask(host, "wrong-bytes");
  assert.throws(() =>
    broker.createTaskFromArtifacts(host, options("wrong-tenant", "other"), [
      input(receipt, bytes),
    ]),
  );
  assertNoTask(host, "wrong-tenant");
  const imported = broker.createTaskFromArtifacts(host, options("imported"), [
    input(receipt, bytes),
  ]);
  assert.equal(host.snapshot(imported.taskId).sensitive, true);
  const publicReceipt = broker.classifyArtifact({
    content: bytes,
    path: "data.txt",
    tenantId: "tenant",
    origin: "operator:review",
    sensitivity: "public",
  });
  assert.equal(
    host.snapshot(
      broker.createTaskFromArtifacts(host, options("public"), [
        input(publicReceipt, bytes),
      ]).taskId,
    ).sensitive,
    false,
  );
  broker.close();
  assert.throws(() => broker.verifyArtifact(receipt, bytes, "tenant"));
});

test("invalid receipts and unsafe paths fail before a sandbox can read input", async (t) => {
  const { host, broker, directory } = setup(t);
  host.createTask(options("task"));
  writeFileSync(join(directory, "input.txt"), "bytes");
  const receipt = broker.classifyArtifact({
    content: Buffer.from("old bytes"),
    path: "input.txt",
    tenantId: "tenant",
    origin: "upload",
  });
  await assert.rejects(
    runGovernedSandbox(host, "task", {
      broker,
      origin: "shell",
      profile: { image: `alpine@sha256:${"a".repeat(64)}` },
      workspace: directory,
      inputFiles: ["input.txt"],
      inputReceipts: [receipt],
      command: ["/bin/true"],
    }),
    /provenance/,
  );
  assert.equal(host.snapshot("task").sensitive, false);
  for (const name of [
    "../escape",
    "/absolute",
    "a\\b",
    "CON",
    "a/../b",
    ".agent-guard-provenance.json",
  ]) {
    assert.throws(() =>
      broker.classifyArtifact({
        content: Buffer.from("x"),
        path: name,
        tenantId: "tenant",
        origin: "upload",
      }),
    );
  }
});

const image = process.env.AGENT_GUARD_SANDBOX_IMAGE;
test(
  "governed sandbox preserves sensitive encoded files and stdout across signed new-root imports",
  { skip: !image },
  async (t) => {
    const { host, broker, directory, key } = setup(t);
    let sends = 0;
    const send = {
      name: "send",
      description: "Host-owned destination",
      resolve: () => ({
        resourceId: "outbox",
        tenantId: "tenant",
        external: true,
        recipient: "receiver",
      }),
      execute: () => {
        sends++;
        return { value: { delivered: true } };
      },
    };
    host.approveTool(send.name, host.registerTool(send));
    host.createTask(options("sensitive-source"));
    const secret = "private-token-for-artifact-test";
    writeFileSync(join(directory, "secret.txt"), secret);
    const sensitive = await runGovernedSandbox(host, "sensitive-source", {
      broker,
      origin: "test:shell",
      profile: { image },
      workspace: directory,
      inputFiles: ["secret.txt"],
      command: [
        "/bin/sh",
        "-c",
        "base64 secret.txt > encoded.txt; cat encoded.txt; cat encoded.txt >&2",
      ],
      exportFiles: ["encoded.txt"],
    });
    assert.equal(host.snapshot("sensitive-source").sensitive, true);
    assert.equal(sensitive.sensitive, true);
    assert.equal(sensitive.inputs[0].payload.sensitivity, "sensitive");
    assert.ok(
      sensitive.artifacts[0].payload.lineage.includes(
        sensitive.inputs[0].payload.artifactId,
      ),
    );
    assert.equal(sensitive.artifacts[0].payload.sensitivity, "sensitive");
    assert.equal(sensitive.stdout.payload.sensitivity, "sensitive");
    assert.equal(sensitive.stderr.payload.sensitivity, "sensitive");
    assert.equal(
      Buffer.from(sensitive.result.stdout.trim(), "base64").toString(),
      secret,
    );
    const bytes = Buffer.from(
      sensitive.result.exports[0].contentBase64,
      "base64",
    );
    const approved = [
      { path: "encoded.txt", sha256: sensitive.artifacts[0].payload.sha256 },
    ];
    const destination = join(directory, "reviewed");
    assert.equal(existsSync(destination), false);
    broker.writeReviewedArtifacts(host, sensitive, approved, destination);
    assert.equal(
      readFileSync(join(destination, "encoded.txt"), "utf8"),
      bytes.toString(),
    );
    assert.equal(
      JSON.parse(
        readFileSync(join(destination, ".agent-guard-provenance.json"), "utf8"),
      ).artifacts[0].payload.sensitivity,
      "sensitive",
    );
    const imported = broker.createTaskFromArtifacts(host, options("new-root"), [
      input(sensitive.artifacts[0], bytes),
    ]);
    await assert.rejects(
      host.prepare(imported.taskId, {
        tool: "send",
        args: { content: bytes.toString() },
      }),
      (error) => error.code === "SENSITIVE_EGRESS_DENIED",
    );
    const stdoutTask = broker.createTaskFromArtifacts(
      host,
      options("stdout-root"),
      [input(sensitive.stdout, sensitive.result.stdout)],
    );
    await assert.rejects(
      host.prepare(stdoutTask.taskId, { tool: "send", args: {} }),
      (error) => error.code === "SENSITIVE_EGRESS_DENIED",
    );
    assert.equal(sends, 0);
    for (const field of ["sensitivity", "tenantId", "sha256"]) {
      const forged = copy(sensitive.artifacts[0]);
      forged.payload[field] = field === "sensitivity" ? "public" : "forged";
      assert.throws(() =>
        broker.createTaskFromArtifacts(host, options(`tampered-${field}`), [
          input(forged, bytes),
        ]),
      );
      assertNoTask(host, `tampered-${field}`);
    }
    const altered = copy(sensitive);
    altered.result.exports[0].contentBase64 =
      Buffer.from("replacement").toString("base64");
    assert.throws(() =>
      broker.writeReviewedArtifacts(
        host,
        altered,
        approved,
        join(directory, "tampered-export"),
      ),
    );
    assert.equal(existsSync(join(directory, "tampered-export")), false);

    // A broker restart and a second output with no input receipt must retain the durable source edge.
    const reopened = new ArtifactBroker({ key, keyId: "host-key-1" });
    t.after(() => reopened.close());
    const descendant = await runGovernedSandbox(host, "new-root", {
      broker: reopened,
      origin: "test:second-shell",
      profile: { image },
      workspace: directory,
      inputFiles: [],
      command: ["/bin/sh", "-c", "echo derivative > next.txt"],
      exportFiles: ["next.txt"],
      inputClassification: "public",
    });
    assert.equal(descendant.sensitive, true);
    assert.ok(
      descendant.artifacts[0].payload.lineageTaskIds.includes(
        "sensitive-source",
      ),
    );
    host.revokeTask("sensitive-source");
    assert.throws(
      () =>
        reopened.createTaskFromArtifacts(host, options("revoked-import"), [
          input(
            descendant.artifacts[0],
            Buffer.from(descendant.result.exports[0].contentBase64, "base64"),
          ),
        ]),
      (error) => error.code === "TASK_REVOKED",
    );
    assertNoTask(host, "revoked-import");
    assert.throws(
      () =>
        broker.writeReviewedArtifacts(
          host,
          sensitive,
          approved,
          join(directory, "revoked-export"),
        ),
      (error) => error.code === "TASK_REVOKED",
    );
    assert.equal(existsSync(join(directory, "revoked-export")), false);

    host.createTask(options("public-source"));
    writeFileSync(join(directory, "public.txt"), "public fixture");
    const publicOutput = await runGovernedSandbox(host, "public-source", {
      broker,
      origin: "test:public-shell",
      profile: { image },
      workspace: directory,
      inputFiles: ["public.txt"],
      inputClassification: "public",
      command: ["/bin/sh", "-c", "cat public.txt > out.txt"],
      exportFiles: ["out.txt"],
    });
    assert.equal(publicOutput.sensitive, false);
    const publicTask = broker.createTaskFromArtifacts(
      host,
      options("public-root"),
      [
        input(
          publicOutput.artifacts[0],
          Buffer.from(publicOutput.result.exports[0].contentBase64, "base64"),
        ),
      ],
    );
    const prepared = await host.prepare(publicTask.taskId, {
      tool: "send",
      args: { content: "public fixture" },
    });
    await host.execute(publicTask.taskId, prepared.id);
    assert.equal(sends, 1);
    // Later source-family taint also restricts an earlier public receipt.
    host.markSensitive("public-source");
    const later = broker.createTaskFromArtifacts(
      host,
      options("public-later-tainted"),
      [
        input(
          publicOutput.artifacts[0],
          Buffer.from(publicOutput.result.exports[0].contentBase64, "base64"),
        ),
      ],
    );
    await assert.rejects(
      host.prepare(later.taskId, { tool: "send", args: {} }),
      (error) => error.code === "SENSITIVE_EGRESS_DENIED",
    );
  },
);

test("sandbox tool rejects unapproved tools, missing grants and extra arguments before Docker dispatch", async (t) => {
  const { host, broker, directory } = setup(t);
  let retained = 0;
  writeFileSync(join(directory, "secret.txt"), "yes");
  const tool = createSandboxTool({
    name: "shell",
    executor: host,
    broker,
    profile: { image: `alpine@sha256:${"a".repeat(64)}` },
    workspace: directory,
    inputFiles: ["secret.txt"],
    tenantId: "tenant",
    resourceId: "workspace",
    origin: "host:fixture",
    onResult: () => {
      retained++;
      return "result";
    },
  });
  const fingerprint = host.registerTool(tool);
  host.createTask({
    ...options("unapproved"),
    grants: [{ tool: "shell", resources: ["workspace"] }],
  });
  await assert.rejects(
    host.prepare("unapproved", {
      tool: "shell",
      args: { command: ["/bin/true"] },
    }),
    (error) => error.code === "TOOL_UNAPPROVED",
  );
  host.approveTool("shell", fingerprint);
  host.createTask(options("no-grant"));
  await assert.rejects(
    host.prepare("no-grant", {
      tool: "shell",
      args: { command: ["/bin/true"] },
    }),
    (error) => error.code === "GRANT_DENIED",
  );
  await assert.rejects(
    host.prepare("unapproved", {
      tool: "shell",
      args: { command: ["/bin/true"], workspace: "/etc" },
    }),
    (error) => error.code === "ARGUMENT_INVALID",
  );
  const prepared = await host.prepare("unapproved", {
    tool: "shell",
    args: { command: ["/bin/true"] },
  });
  assert.match(prepared.action.resourceVersion, /^hmac-sha256:[a-f0-9]{64}$/);
  assert.notEqual(
    prepared.action.resourceVersion.split(":")[1],
    createHash("sha256").update("yes").digest("hex"),
  );
  assert.equal(
    JSON.stringify(prepared).includes(
      createHash("sha256").update("yes").digest("hex"),
    ),
    false,
  );
  assert.equal(host.snapshot("unapproved").sensitive, false);
  await assert.rejects(
    host.execute("unapproved", prepared.id),
    (error) => error.code === "APPROVAL_REQUIRED",
  );
  assert.equal(host.snapshot("unapproved").calls, 0);
  assert.equal(host.snapshot("no-grant").calls, 0);
  assert.equal(retained, 0);
});

test(
  "real governed sandbox tool uses durable approval budgets input versions and cancellation",
  { skip: !image },
  async (t) => {
    const { host, broker, directory } = setup(t);
    const retained = [];
    writeFileSync(join(directory, "input.txt"), "public fixture");
    const tool = createSandboxTool({
      name: "shell",
      executor: host,
      broker,
      profile: { image, timeoutMs: 30_000 },
      workspace: directory,
      inputFiles: ["input.txt"],
      exportFiles: ["out.txt"],
      tenantId: "tenant",
      resourceId: "workspace",
      origin: "host:public-fixture",
      inputClassification: "public",
      onResult: (result, context) => {
        retained.push({ result, context });
        return `result-${retained.length}`;
      },
    });
    host.approveTool("shell", host.registerTool(tool));
    const task = (id) =>
      host.createTask({
        ...options(id),
        grants: [{ tool: "shell", resources: ["workspace"] }],
        budget: {
          maxCalls: 1,
          maxConcurrent: 1,
          maxCost: 0,
          deadline: Date.now() + 60_000,
        },
      });
    const prepare = async (id, command) => {
      const prepared = await host.prepare(id, {
        tool: "shell",
        args: { command },
      });
      const approvalId = host.approve(prepared.id, {
        approverId: "operator",
        expiresAt: Date.now() + 30_000,
      });
      return { prepared, approvalId };
    };
    task("changed-input");
    const changed = await prepare("changed-input", [
      "/bin/sh",
      "-c",
      "cat input.txt > out.txt",
    ]);
    writeFileSync(join(directory, "input.txt"), "changed fixture");
    await assert.rejects(
      host.execute("changed-input", changed.prepared.id, {
        approvalId: changed.approvalId,
      }),
      (error) => error.code === "TOOL_CHANGED",
    );
    assert.equal(retained.length, 0);
    task("allowed-shell");
    const allowed = await prepare("allowed-shell", [
      "/bin/sh",
      "-c",
      'cat input.txt > out.txt; head -c 20000 /dev/zero | tr "\\000" x',
    ]);
    const value = await host.execute("allowed-shell", allowed.prepared.id, {
      approvalId: allowed.approvalId,
    });
    assert.equal(value.resultId, "result-1");
    assert.equal(value.stdout.truncated, true);
    assert.equal(Buffer.byteLength(value.stdout.text), 16 * 1024);
    assert.equal(retained[0].result.result.stdout.length, 20_000);
    assert.equal(retained[0].result.stdout.payload.bytes, 20_000);
    assert.equal(host.snapshot("allowed-shell").calls, 1);
    assert.equal(host.snapshot("allowed-shell").concurrent, 0);
    await assert.rejects(
      host.prepare("allowed-shell", {
        tool: "shell",
        args: { command: ["/bin/true"] },
      }),
      (error) => error.code === "CALL_BUDGET_EXCEEDED",
    );

    task("cancel-shell");
    const cancelled = await prepare("cancel-shell", [
      "/bin/sh",
      "-c",
      "sleep 27; echo done > out.txt",
    ]);
    const running = host.execute("cancel-shell", cancelled.prepared.id, {
      approvalId: cancelled.approvalId,
    });
    // Attach rejection handling immediately while waiting for the actual guest workload.
    const outcome = running.then(
      (value) => ({ value }),
      (error) => ({ error }),
    );
    const stop = Date.now() + 15_000;
    let container;
    while (Date.now() < stop && !container) {
      const listed = spawnSync(
        "docker",
        ["ps", "--filter", "name=agent-guard-", "--format", "{{.ID}}"],
        { encoding: "utf8", timeout: 5000 },
      );
      assert.equal(listed.status, 0);
      for (const id of listed.stdout.trim().split("\n").filter(Boolean)) {
        const top = spawnSync("docker", ["top", id], {
          encoding: "utf8",
          timeout: 5000,
        });
        if (top.status === 0 && top.stdout.includes("sleep 27")) {
          container = id;
          break;
        }
      }
      if (!container) await new Promise((resolve) => setTimeout(resolve, 50));
    }
    assert.ok(container, "real guest workload started before cancellation");
    host.cancel("cancel-shell", cancelled.prepared.id);
    const result = await outcome;
    assert.equal(result.error?.code, "EXECUTION_ABORTED");
    assert.equal(retained.length, 1);
    assert.notEqual(
      spawnSync("docker", ["inspect", container], {
        encoding: "utf8",
        timeout: 5000,
      }).status,
      0,
    );
    assert.equal(
      host.execution("cancel-shell", cancelled.prepared.id).status,
      "UNKNOWN",
    );
    assert.equal(
      host.snapshot("cancel-shell").concurrent,
      1,
      "cancellation retains reservation pending host reconciliation",
    );
  },
);
