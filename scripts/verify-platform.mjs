import { spawnSync } from 'node:child_process';
import { mkdirSync, writeFileSync } from 'node:fs';
import { release, arch } from 'node:os';
import { fileURLToPath } from 'node:url';
import { join } from 'node:path';
import { isEntry } from '../examples/providers/replay.mjs';

export const REQUIRED_RUNTIME_TESTS = Object.freeze([
  'real Linux Docker runtime enforces isolation and copies only selected files',
  'raw: content swapped as the broker starts staging cannot reach Docker under the old approval',
  'attested: content swapped as the broker starts staging cannot reach Docker under the old approval',
  'real Docker export rejects symlinks and host input symlinks',
  'real Docker time and output limits terminate workloads and clean up containers',
  'governed sandbox preserves sensitive encoded files and stdout across signed new-root imports',
  'real governed sandbox tool uses durable approval budgets input versions and cancellation',
  'real governed sandbox imports an attested build and rejects derivatives after policy rotation',
  'real isolated MCP deployment enforces credential custody transport scope lifecycle and cleanup',
  'real HTTPS MCP credentials enforce verified access token lifecycle and cleanup',
  'additional CA trust is bounded and belongs only to its exact allowed HTTPS origin',
  'trusted CA does not disable hostname validation or grant private network access',
  'actual socket lookup rejects private and mixed answers and rechecks rebinding after a cancelled lookup',
]);
const platforms = { Linux: 'linux', macOS: 'darwin', Windows: 'win32' };
export function requiredPlatformTests(host) {
  const inputTests =
    host === 'Windows'
      ? [
          'Windows pinned workspace read returns exact bytes and rejects junction, hardlink, and alternate-stream inputs',
          'Windows concurrent workspace junction swaps cannot return outside bytes',
        ]
      : [
          'bounded input capture accepts the selected file and rejects a FIFO without blocking',
          'a directory swap during capture cannot send an outside file to the guest',
        ];
  return [...REQUIRED_RUNTIME_TESTS, ...inputTests];
}
export function validatePlatformImages({ image, mcpImage }) {
  const pinned = value =>
    typeof value === 'string' && /^[a-z0-9][a-z0-9._/:\-]*@sha256:[a-f0-9]{64}$/.test(value) && !value.includes('..');
  if (!pinned(image) || !pinned(mcpImage))
    throw new Error('Platform gate requires reviewed, locally installed sandbox and MCP image digests');
  return { image, mcpImage };
}
export function validatePlatformRun({ expectedHost, actualPlatform, status, output }) {
  if (!Object.hasOwn(platforms, expectedHost) || platforms[expectedHost] !== actualPlatform)
    throw new Error('Platform gate host does not match the required matrix OS');
  if (status !== 0 || typeof output !== 'string') throw new Error('Platform runtime tests failed');
  const tap = output.replaceAll('\r\n', '\n');
  const count = name => {
    const matches = [...tap.matchAll(new RegExp(`^# ${name} (\\d+)$`, 'gm'))];
    if (matches.length !== 1) throw new Error(`Missing or ambiguous TAP ${name} count`);
    return Number(matches[0][1]);
  };
  const required = requiredPlatformTests(expectedHost);
  const tests = count('tests'),
    passed = count('pass');
  if (
    tests < required.length ||
    passed !== tests ||
    count('fail') !== 0 ||
    count('cancelled') !== 0 ||
    count('skipped') !== 0 ||
    count('todo') !== 0
  )
    throw new Error('Platform gate requires every test to pass without skips');
  for (const name of required) {
    const expected = name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    if (![...tap.matchAll(new RegExp(`^ok \\d+ - ${expected}$`, 'gm'))].length)
      throw new Error(`Missing unskipped runtime test: ${name}`);
  }
  return {
    tests,
    passed,
    skipped: 0,
    runtimeTests: required,
  };
}

function main() {
  const root = fileURLToPath(new URL('../', import.meta.url));
  const image = process.env.AGENT_GUARD_SANDBOX_IMAGE;
  const mcpImage = process.env.AGENT_GUARD_MCP_ISOLATION_IMAGE;
  const expectedHost = process.env.AGENT_GUARD_EXPECTED_HOST;
  const evidence = {
    time: new Date().toISOString(),
    expectedHost,
    platform: process.platform,
    release: release(),
    arch: arch(),
    node: process.version,
    image,
    mcpImage,
    passed: false,
  };
  try {
    if (!Object.hasOwn(platforms, expectedHost ?? '') || platforms[expectedHost] !== process.platform)
      throw new Error('Platform gate requires the exact expected matrix host OS');
    validatePlatformImages({ image, mcpImage });
    const docker = spawnSync('docker', ['version', '--format', '{{json .}}'], {
      cwd: root,
      encoding: 'utf8',
      timeout: 15_000,
      maxBuffer: 1_048_576,
    });
    if (docker.status !== 0) throw new Error('Docker unavailable');
    evidence.docker = JSON.parse(docker.stdout);
    const tests = spawnSync(
      process.execPath,
      [
        '--test',
        '--test-reporter=tap',
        'packages/executor/test/sandbox.test.mjs',
        'packages/executor/test/sandbox-staged-input-version.test.mjs',
        expectedHost === 'Windows'
          ? 'packages/executor/test/workspace-input-windows.test.mjs'
          : 'packages/executor/test/workspace-input.test.mjs',
        'packages/executor/test/artifacts.test.mjs',
        'packages/executor/test/build-artifact-import.test.mjs',
        'scripts/mcp-isolation.test.mjs',
        'packages/mcp/test/credentials.test.mjs',
        'packages/executor/test/network.test.mjs',
      ],
      {
        cwd: root,
        env: process.env,
        encoding: 'utf8',
        timeout: 240_000,
        maxBuffer: 2_097_152,
      },
    );
    evidence.output = tests.stdout ?? '';
    evidence.error = tests.stderr ?? '';
    evidence.counts = validatePlatformRun({
      expectedHost,
      actualPlatform: process.platform,
      status: tests.status,
      output: evidence.output,
    });
    evidence.passed = true;
  } catch (error) {
    evidence.error = error instanceof Error ? error.message : 'Platform verification failed';
  }
  mkdirSync(join(root, 'artifacts'), { recursive: true });
  writeFileSync(join(root, 'artifacts/platform-evidence.json'), JSON.stringify(evidence, null, 2) + '\n');
  process.stdout.write(evidence.output ?? '');
  if (!evidence.passed) {
    process.stderr.write(`${evidence.error}\n`);
    process.exitCode = 1;
  }
}
if (isEntry(import.meta)) main();
