import test from "node:test";
import assert from "node:assert/strict";
import {
  REQUIRED_RUNTIME_TESTS,
  requiredPlatformTests,
  validatePlatformRun,
  validatePlatformImages,
} from "./verify-platform.mjs";
const tap = (names = requiredPlatformTests("macOS")) =>
  `${names.map((name, index) => `ok ${index + 1} - ${name}`).join("\n")}\n# tests ${names.length}\n# pass ${names.length}\n# fail 0\n# cancelled 0\n# skipped 0\n# todo 0\n`;
const run = (output = tap(), overrides = {}) =>
  validatePlatformRun({
    expectedHost: "macOS",
    actualPlatform: "darwin",
    status: 0,
    output,
    ...overrides,
  });
test("platform verification requires the exact matrix OS and all real runtime tests", () => {
  assert.equal(run().passed, requiredPlatformTests("macOS").length);
  assert.throws(() => run(tap(), { expectedHost: "Windows" }), /host/);
  assert.throws(() => run(tap(), { expectedHost: undefined }), /host/);
  assert.throws(() => run(tap(), { status: 1 }), /failed/);
  assert.throws(
    () => run(tap().replace(REQUIRED_RUNTIME_TESTS[0], "unit test instead")),
    /Missing unskipped/,
  );
});
test("passing exit status cannot disguise skipped, canceled, filtered or missing tests", () => {
  assert.throws(
    () => run(tap().replace("# skipped 0", "# skipped 1")),
    /without skips/,
  );
  assert.throws(
    () => run(tap().replace("# cancelled 0", "# cancelled 1")),
    /without skips/,
  );
  assert.throws(
    () => run(tap().replace("# todo 0", "# todo 1")),
    /without skips/,
  );
  assert.throws(
    () => run(tap().replace(`${REQUIRED_RUNTIME_TESTS[0]}\n`, `${REQUIRED_RUNTIME_TESTS[0]} # SKIP\n`)),
    /Missing unskipped/,
  );
  assert.throws(() => run(""), /TAP/);
  assert.throws(() => run(tap() + "# skipped 0\n"), /ambiguous/);
});

test("platform gate requires pinned sandbox and MCP images together", () => {
  const image = `alpine@sha256:${"a".repeat(64)}`;
  const mcpImage = `node@sha256:${"b".repeat(64)}`;
  assert.deepEqual(validatePlatformImages({ image, mcpImage }), {
    image,
    mcpImage,
  });
  for (const values of [
    { image },
    { mcpImage },
    { image, mcpImage: "node:latest" },
    { image: "alpine:3.21", mcpImage },
    { image, mcpImage: `../node@sha256:${"b".repeat(64)}` },
  ])
    assert.throws(() => validatePlatformImages(values), /image digests/);
});

test("platform evidence requires an attested import through the real sandbox", () => {
  const name = "real governed sandbox imports an attested build and rejects derivatives after policy rotation";
  assert.ok(REQUIRED_RUNTIME_TESTS.includes(name));
  assert.throws(() => run(tap().replace(name, "older artifact receipt checks")), /Missing unskipped/);
});

test("the old sandbox-only evidence cannot satisfy the joined MCP platform gate", () => {
  const mcp = REQUIRED_RUNTIME_TESTS.find((name) =>
    name.includes("isolated MCP deployment"),
  );
  assert.ok(mcp);
  assert.throws(
    () => run(tap().replace(mcp, "unrelated passing unit test")),
    /Missing unskipped/,
  );
});

test("platform evidence requires real HTTPS credential lifecycle and socket DNS checks", () => {
  const transportChecks = REQUIRED_RUNTIME_TESTS.filter((name) =>
    /HTTPS|hostname|socket lookup/.test(name),
  );
  assert.equal(transportChecks.length, 4);
  for (const name of transportChecks) {
    assert.throws(
      () => run(tap().replace(name, "older passing fixture")),
      /Missing unskipped/,
    );
    assert.throws(
      () => run(tap().replace(`${name}\n`, `${name} # SKIP\n`)),
      /Missing unskipped/,
    );
  }
});

test("workspace file capture evidence must match the running host", () => {
  const windows = { expectedHost: "Windows", actualPlatform: "win32" };
  const names = requiredPlatformTests("Windows");
  assert.equal(run(tap(names), windows).passed, names.length);
  assert.throws(() => run(tap(), windows), /Missing unskipped/);
  assert.throws(() => run(tap(names)), /without skips|Missing unskipped/);
});
