import test from "node:test";
import assert from "node:assert/strict";
import {
  REQUIRED_RUNTIME_TESTS,
  validatePlatformRun,
} from "./verify-platform.mjs";
const tap = () =>
  `${REQUIRED_RUNTIME_TESTS.map((name, index) => `ok ${index + 1} - ${name}`).join("\n")}\n# tests ${REQUIRED_RUNTIME_TESTS.length}\n# pass ${REQUIRED_RUNTIME_TESTS.length}\n# fail 0\n# cancelled 0\n# skipped 0\n# todo 0\n`;
const run = (output = tap(), overrides = {}) =>
  validatePlatformRun({
    expectedHost: "macOS",
    actualPlatform: "darwin",
    status: 0,
    output,
    ...overrides,
  });
test("platform verification requires the exact matrix OS and all real runtime tests", () => {
  assert.equal(run().passed, REQUIRED_RUNTIME_TESTS.length);
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
    () =>
      run(
        tap()
          .replace("ok 1 -", "ok 1 -")
          .replace(
            `${REQUIRED_RUNTIME_TESTS[0]}\n`,
            `${REQUIRED_RUNTIME_TESTS[0]} # SKIP\n`,
          ),
      ),
    /Missing unskipped/,
  );
  assert.throws(() => run(""), /TAP/);
  assert.throws(() => run(tap() + "# skipped 0\n"), /ambiguous/);
});
