import { spawnSync } from "node:child_process";
import { mkdirSync, writeFileSync } from "node:fs";
import { release, arch } from "node:os";
import { fileURLToPath } from "node:url";
import { join, resolve } from "node:path";

export const REQUIRED_RUNTIME_TESTS = Object.freeze([
  "real Linux Docker runtime enforces isolation and copies only selected files",
  "real Docker export rejects symlinks and host input symlinks",
  "real Docker time and output limits terminate workloads and clean up containers",
  "governed sandbox preserves sensitive encoded files and stdout across signed new-root imports",
  "real governed sandbox tool uses durable approval budgets input versions and cancellation",
]);
const platforms = { Linux: "linux", macOS: "darwin", Windows: "win32" };
export function validatePlatformRun({
  expectedHost,
  actualPlatform,
  status,
  output,
}) {
  if (
    !Object.hasOwn(platforms, expectedHost) ||
    platforms[expectedHost] !== actualPlatform
  )
    throw new Error("Platform gate host does not match the required matrix OS");
  if (status !== 0 || typeof output !== "string")
    throw new Error("Platform runtime tests failed");
  const tap = output.replaceAll("\r\n", "\n");
  const count = (name) => {
    const matches = [...tap.matchAll(new RegExp(`^# ${name} (\\d+)$`, "gm"))];
    if (matches.length !== 1)
      throw new Error(`Missing or ambiguous TAP ${name} count`);
    return Number(matches[0][1]);
  };
  const tests = count("tests"),
    passed = count("pass");
  if (
    tests < REQUIRED_RUNTIME_TESTS.length ||
    passed !== tests ||
    count("fail") !== 0 ||
    count("cancelled") !== 0 ||
    count("skipped") !== 0 ||
    count("todo") !== 0
  )
    throw new Error("Platform gate requires every test to pass without skips");
  for (const name of REQUIRED_RUNTIME_TESTS) {
    const expected = name.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    if (![...tap.matchAll(new RegExp(`^ok \\d+ - ${expected}$`, "gm"))].length)
      throw new Error(`Missing unskipped runtime test: ${name}`);
  }
  return {
    tests,
    passed,
    skipped: 0,
    runtimeTests: [...REQUIRED_RUNTIME_TESTS],
  };
}

function main() {
  const root = fileURLToPath(new URL("../", import.meta.url));
  const image = process.env.AGENT_GUARD_SANDBOX_IMAGE;
  const expectedHost = process.env.AGENT_GUARD_EXPECTED_HOST;
  const evidence = {
    time: new Date().toISOString(),
    expectedHost,
    platform: process.platform,
    release: release(),
    arch: arch(),
    node: process.version,
    image,
    passed: false,
  };
  try {
    if (
      !Object.hasOwn(platforms, expectedHost ?? "") ||
      platforms[expectedHost] !== process.platform
    )
      throw new Error(
        "Platform gate requires the exact expected matrix host OS",
      );
    if (!image || !/^[a-z0-9][a-z0-9._/:\-]*@sha256:[a-f0-9]{64}$/.test(image))
      throw new Error(
        "Platform gate requires an explicit reviewed, locally installed image digest",
      );
    const docker = spawnSync("docker", ["version", "--format", "{{json .}}"], {
      cwd: root,
      encoding: "utf8",
      timeout: 15_000,
      maxBuffer: 1_048_576,
    });
    if (docker.status !== 0) throw new Error("Docker unavailable");
    evidence.docker = JSON.parse(docker.stdout);
    const tests = spawnSync(
      process.execPath,
      [
        "--test",
        "--test-reporter=tap",
        "packages/executor/test/sandbox.test.mjs",
        "packages/executor/test/artifacts.test.mjs",
      ],
      {
        cwd: root,
        env: process.env,
        encoding: "utf8",
        timeout: 120_000,
        maxBuffer: 2_097_152,
      },
    );
    evidence.output = tests.stdout ?? "";
    evidence.error = tests.stderr ?? "";
    evidence.counts = validatePlatformRun({
      expectedHost,
      actualPlatform: process.platform,
      status: tests.status,
      output: evidence.output,
    });
    evidence.passed = true;
  } catch (error) {
    evidence.error =
      error instanceof Error ? error.message : "Platform verification failed";
  }
  mkdirSync(join(root, "artifacts"), { recursive: true });
  writeFileSync(
    join(root, "artifacts/platform-evidence.json"),
    JSON.stringify(evidence, null, 2) + "\n",
  );
  process.stdout.write(evidence.output ?? "");
  if (!evidence.passed) {
    process.stderr.write(`${evidence.error}\n`);
    process.exitCode = 1;
  }
}
if (
  process.argv[1] &&
  resolve(process.argv[1]) === fileURLToPath(import.meta.url)
)
  main();
