import test from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import {
  mkdtempSync,
  writeFileSync,
  readFileSync,
  rmSync,
  symlinkSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { spawnSync } from "node:child_process";
import {
  validateSandboxProfile,
  buildDockerCreateArgs,
  readSandboxArchive,
  writeReviewedExports,
  runDockerSandbox,
} from "../dist/sandbox.js";
const image =
  "alpine@sha256:bbfcd601d7cd20d35bb0b8b866ad1a8a0d107ca3e1c20870c75c5ce2c1186d30";
const name = "agent-guard-11111111-2222-3333-4444-555555555555";
function directory(t) {
  const dir = mkdtempSync(join(tmpdir(), "agent-guard-sandbox-test-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  return dir;
}
function tar(entries) {
  const blocks = [];
  for (const { path, type = "0", data = "", link = "" } of entries) {
    const body = Buffer.from(data),
      header = Buffer.alloc(512);
    header.write(path, 0, 100);
    header.write("0000600\0", 100, 8);
    header.write("0001750\0", 108, 8);
    header.write("0001750\0", 116, 8);
    header.write(body.length.toString(8).padStart(11, "0") + "\0", 124, 12);
    header.write("00000000000\0", 136, 12);
    header.fill(32, 148, 156);
    header.write(type, 156);
    header.write(link, 157, 100);
    header.write("ustar\0", 257);
    header.write("00", 263);
    const checksum = header.reduce((sum, value) => sum + value, 0);
    header.write(checksum.toString(8).padStart(6, "0") + "\0 ", 148, 8);
    blocks.push(header, body, Buffer.alloc((512 - (body.length % 512)) % 512));
  }
  return Buffer.concat([...blocks, Buffer.alloc(1024)]);
}

test("profile has no network, privilege, host-mount or image-tag escape options", () => {
  assert.equal(validateSandboxProfile({ image }).pidsLimit, 64);
  for (const profile of [
    { image: "alpine:latest" },
    { image, network: "host" },
    { image, privileged: true },
    { image, memoryMb: 0 },
    { image, cpus: NaN },
    { image, timeoutMs: Infinity },
    { image, mounts: ["/var/run/docker.sock"] },
  ])
    assert.throws(() => validateSandboxProfile(profile));
  const args = buildDockerCreateArgs({ image }, resolve("staging"), name);
  for (const required of [
    "--network=none",
    "--read-only",
    "--user=1000:1000",
    "--cap-drop=ALL",
    "--security-opt=no-new-privileges:true",
    "--pull=never",
    "--init",
    "--no-healthcheck",
    "--log-driver=none",
  ])
    assert.ok(args.includes(required));
  assert.equal(args.filter((arg) => arg.startsWith("type=bind")).length, 1);
  assert.match(
    args.find((arg) => arg.startsWith("type=bind")),
    /target=\/input,readonly/,
  );
  assert.throws(() =>
    buildDockerCreateArgs(
      { image },
      "/tmp/source,target=/var/run/docker.sock",
      name,
    ),
  );
});

test("archive parsing rejects traversal, links, devices, extensions, duplicates, truncation and excess output", () => {
  const okay = tar([{ path: "./answer.txt", data: "answer" }]);
  assert.equal(
    readSandboxArchive(okay, ["answer.txt"], 100)[0].contentBase64,
    Buffer.from("answer").toString("base64"),
  );
  const malicious = [
    tar([{ path: "../escape", data: "bad" }]),
    tar([{ path: "/absolute", data: "bad" }]),
    tar([{ path: "./x", type: "2", link: "/etc/passwd" }]),
    tar([{ path: "./x", type: "1", link: "./answer.txt" }]),
    tar([{ path: "./x", type: "3" }]),
    tar([{ path: "./x", type: "x", data: "pax" }]),
    tar([
      { path: "./x", data: "1" },
      { path: "./X", data: "2" },
    ]),
    okay.subarray(0, 700),
  ];
  for (const archive of malicious)
    assert.throws(() => readSandboxArchive(archive, [], 100));
  assert.throws(() => readSandboxArchive(okay, ["answer.txt"], 2));
  assert.throws(() => readSandboxArchive(okay, ["missing.txt"], 100));
  assert.throws(() => readSandboxArchive(okay, ["C:/escape"], 100));
});

test("reviewed export verifies exact hashes, only creates a fresh destination, and never overwrites", (t) => {
  const dir = directory(t),
    files = readSandboxArchive(
      tar([{ path: "./nested/answer.txt", data: "safe" }]),
      ["nested/answer.txt"],
      100,
    );
  const result = { exports: files };
  const approved = files.map(({ path, sha256 }) => ({ path, sha256 }));
  assert.throws(() =>
    writeReviewedExports(
      result,
      [{ path: files[0].path, sha256: "0".repeat(64) }],
      join(dir, "bad"),
    ),
  );
  const output = writeReviewedExports(result, approved, join(dir, "reviewed"));
  assert.equal(readFileSync(output[0], "utf8"), "safe");
  assert.throws(() =>
    writeReviewedExports(result, approved, join(dir, "reviewed")),
  );
  const tampered = {
    exports: [
      { ...files[0], contentBase64: Buffer.from("evil").toString("base64") },
    ],
  };
  assert.throws(() =>
    writeReviewedExports(tampered, approved, join(dir, "tampered")),
  );
});

const integrationImage = process.env.AGENT_GUARD_SANDBOX_IMAGE;
const integration = { skip: !integrationImage, timeout: 60_000 };
test(
  "real Linux Docker runtime enforces isolation and copies only selected files",
  integration,
  async (t) => {
    const dir = directory(t);
    writeFileSync(join(dir, "input.txt"), "selected");
    writeFileSync(join(dir, "unselected-secret.txt"), "never copied");
    const result = await runDockerSandbox({
      profile: { image: integrationImage },
      workspace: dir,
      inputFiles: ["input.txt"],
      exportFiles: ["result.txt"],
      command: [
        "/bin/sh",
        "-ec",
        `
    test "$(id -u)" = 1000
    test "$(cat /sys/fs/cgroup/pids.max)" = 64
    test "$(cat /sys/fs/cgroup/memory.max)" = 268435456
    test "$(cut -d ' ' -f 1 /sys/fs/cgroup/cpu.max)" = 100000
    grep -q '^CapEff:[[:space:]]*0000000000000000$' /proc/self/status
    grep -q '^NoNewPrivs:[[:space:]]*1$' /proc/self/status
    test "$(ls /sys/class/net)" = lo
    test ! -e /var/run/docker.sock
    test ! -e /run/containerd/containerd.sock
    test ! -e /input/unselected-secret.txt
    test ! -e /workspace/unselected-secret.txt
    if touch /etc/agent-guard-escape 2>/dev/null; then exit 71; fi
    if echo changed > /input/input.txt 2>/dev/null; then exit 72; fi
    test "$(cat input.txt)" = selected
    echo isolated > result.txt
    printf 'isolation verified'
  `,
      ],
    });
    assert.equal(result.exitCode, 0, result.stderr);
    assert.equal(result.stdout, "isolation verified");
    assert.equal(
      Buffer.from(result.exports[0].contentBase64, "base64").toString(),
      "isolated\n",
    );
    assert.equal(readFileSync(join(dir, "input.txt"), "utf8"), "selected");
  },
);

test(
  "real Docker export rejects symlinks and host input symlinks",
  integration,
  async (t) => {
    const dir = directory(t);
    writeFileSync(join(dir, "input.txt"), "selected");
    await assert.rejects(
      runDockerSandbox({
        profile: { image: integrationImage },
        workspace: dir,
        inputFiles: ["input.txt"],
        command: [
          "/bin/sh",
          "-c",
          "ln -s /etc/passwd leak; echo ok > result.txt",
        ],
        exportFiles: ["result.txt"],
      }),
      /reject symlinks/,
    );
    symlinkSync(join(dir, "input.txt"), join(dir, "link.txt"));
    await assert.rejects(
      runDockerSandbox({
        profile: { image: integrationImage },
        workspace: dir,
        inputFiles: ["link.txt"],
        command: ["/bin/true"],
      }),
      /symlinks/,
    );
  },
);

test(
  "real Docker time and output limits terminate workloads and clean up containers",
  integration,
  async (t) => {
    const dir = directory(t);
    const containers = () =>
      spawnSync("docker", ["ps", "-aq", "--filter", `label=io.shielda.agent-guard.owner-pid=${process.pid}`], {
        encoding: "utf8",
      }).stdout.trim();
    const before = containers();
    await assert.rejects(
      runDockerSandbox({
        profile: { image: integrationImage, timeoutMs: 100 },
        workspace: dir,
        inputFiles: [],
        command: ["/bin/sleep", "30"],
      }),
      /time limit/,
    );
    await assert.rejects(
      runDockerSandbox({
        profile: { image: integrationImage, maxOutputBytes: 128 },
        workspace: dir,
        inputFiles: [],
        command: ["/bin/sh", "-c", "yes output"],
      }),
      /byte limit/,
    );
    assert.equal(containers(), before);
  },
);
