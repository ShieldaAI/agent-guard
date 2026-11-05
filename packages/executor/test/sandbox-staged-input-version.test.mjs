import test from "node:test";
import assert from "node:assert/strict";
import childProcess from "node:child_process";
import { syncBuiltinESMExports } from "node:module";
import { randomBytes } from "node:crypto";
import { mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ArtifactBroker, createSandboxTool, DurableExecutor } from "../dist/index.js";

const fixture = JSON.parse(readFileSync(new URL("./fixtures/packed-build-attestation.json", import.meta.url), "utf8"));
const original = Buffer.from("fixture");
const image = `alpine@sha256:${"a".repeat(64)}`;

for (const profile of ["raw", "attested"]) {
  test(`${profile}: content swapped as the broker starts staging cannot reach Docker under the old approval`, async (t) => {
    const workspace = realpathSync(mkdtempSync(join(tmpdir(), "agent-guard-staged-input-")));
    const file = join(workspace, fixture.rule.path);
    writeFileSync(file, original);
    const executor = new DurableExecutor({ database: ":memory:", encryptionKey: randomBytes(32) });
    const broker = new ArtifactBroker({ key: randomBytes(32), keyId: "fixture-host",
      ...(profile === "attested" ? { buildPolicy: { artifacts: [fixture.rule] } } : {}) });
    t.after(() => { broker.close(); executor.close(); rmSync(workspace, { recursive: true, force: true }); });

    const inputReceipts = profile === "attested" ? [broker.admitBuildArtifact({ content: original,
      path: fixture.rule.path, tenantId: fixture.rule.tenantId, attestation: fixture.attestation })] : [];
    const definition = createSandboxTool({ name: "shell", broker, executor, profile: { image }, workspace,
      tenantId: fixture.rule.tenantId, resourceId: "workspace", origin: "fixture",
      inputFiles: [fixture.rule.path], inputReceipts, inputClassification: "public",
      onResult() { assert.fail("No fake or real guest output was expected"); } });
    executor.approveTool("shell", executor.registerTool(definition));

    // The old adapter had already compared the approved version when it called this method.
    const stage = broker.runGovernedSandbox.bind(broker);
    let replace = true, brokerCalls = 0;
    t.mock.method(broker, "runGovernedSandbox", (...args) => {
      brokerCalls++;
      if (replace) writeFileSync(file, "swapped"); // Same file, path and byte length.
      return stage(...args);
    });

    // Count at the first Docker boundary. The unchanged control must reach it, the race must not.
    let dockerCalls = 0;
    const originalSpawn = childProcess.spawn;
    childProcess.spawn = command => {
      assert.equal(command, "docker"); dockerCalls++;
      throw new Error("Stop before contacting Docker");
    };
    syncBuiltinESMExports();
    t.after(() => { childProcess.spawn = originalSpawn; syncBuiltinESMExports(); });
    const dockerHost = process.env.DOCKER_HOST;
    delete process.env.DOCKER_HOST;
    t.after(() => { if (dockerHost !== undefined) process.env.DOCKER_HOST = dockerHost; });

    for (const id of ["swapped", "unchanged"]) {
      writeFileSync(file, original);
      const task = { id, tenantId: fixture.rule.tenantId, principalId: "fixture-host",
        grants: [{ tool: "shell", resources: ["workspace"] }],
        budget: { maxCalls: 1, maxConcurrent: 1, maxCost: 0, deadline: Date.now() + 60_000 } };
      if (profile === "attested") broker.createTaskFromArtifacts(executor, task, [
        { envelope: inputReceipts[0], contentBase64: original.toString("base64") },
      ]);
      else executor.createTask(task);
      const prepared = await executor.prepare(id, { tool: "shell", args: { command: ["/bin/cat", fixture.rule.path] } });
      const approvalId = executor.approve(prepared.id, { approverId: "fixture-reviewer", expiresAt: Date.now() + 30_000 });
      await assert.rejects(executor.execute(id, prepared.id, { approvalId }), error => {
        assert.equal(brokerCalls, replace ? 1 : 2);
        assert.equal(dockerCalls, replace ? 0 : 1, "only unchanged approved bytes may reach Docker");
        assert.equal(error.code, replace ? "TOOL_CHANGED" : "TOOL_FAILED");
        return true;
      });
      replace = false;
    }
  });
}
