import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  REQUIRED_MCP_CHECKS,
  validateMcpIsolationReport,
  verifyMcpIsolation,
  cleanupGuestStage,
  parseOptions,
} from './verify-mcp-isolation.mjs';
const image = 'node@sha256:' + 'a'.repeat(64);
const passing = () => ({
  version: 1,
  image,
  isolation: 'linux-container-network-none',
  host: { platform: 'linux', architecture: 'arm64', node: 'v24.22.1' },
  guestNode: 'v24.22.1',
  sourceSha256: 'b'.repeat(64),
  fixtureSha256: 'c'.repeat(64),
  cleanup: true,
  checks: REQUIRED_MCP_CHECKS.map(name => ({ name, passed: true })),
  local: { approvedWrites: 1 },
  remote: {
    approvedCalls: 1,
    redirectLeaks: 0,
    claimDenials: 7,
    reconciledAuthFailures: 7,
  },
});

test('MCP deployment gate requires every positive negative lifecycle and cleanup observation', () => {
  assert.equal(validateMcpIsolationReport(passing()), true);
  for (const change of [
    r => r.checks.pop(),
    r => r.checks.push(r.checks[0]),
    r => (r.checks[0].passed = false),
    r => (r.checks[0].name = 'unknown'),
    r => (r.cleanup = false),
    r => (r.failure = { stage: 'x' }),
    r => (r.cleanupFailures = [{ container: 'fixture' }]),
    r => (r.local.approvedWrites = 0),
    r => (r.remote.approvedCalls = 0),
    r => (r.remote.redirectLeaks = 1),
    r => delete r.remote.claimDenials,
    r => (r.remote.reconciledAuthFailures = 6),
    r => (r.image = 'node:latest'),
    r => (r.host.platform = 'untested'),
    r => (r.host.architecture = false),
    r => (r.host.architecture = 'untested'),
    r => (r.host.node = 42),
    r => (r.host.node = 'v24.'),
    r => (r.expectedHost = 'macOS'),
    r => (r.expectedHost = ['Linux']),
    r => (r.guestNode = ''),
    r => (r.guestNode = ['v24.']),
    r => (r.guestNode = 'v24.'),
    r => delete r.sourceSha256,
    r => delete r.fixtureSha256,
    r => (r.sourceSha256 = ['b'.repeat(64)]),
    r => (r.fixtureSha256 = 'invalid'),
    r => (r.image = [image]),
    r => (r.checks = null),
    r => (r.checks = [null]),
  ]) {
    const report = passing();
    change(report);
    assert.equal(validateMcpIsolationReport(report), false);
  }
  assert.equal(validateMcpIsolationReport(null), false);
});

test('failed or uncreated disposable containers cannot prevent private staging cleanup', () => {
  for (const created of [false, true]) {
    const directory = mkdtempSync(join(tmpdir(), 'guard-stage-cleanup-')),
      input = join(directory, 'input');
    mkdirSync(input);
    writeFileSync(join(input, 'fixture'), 'synthetic');
    let calls = 0;
    const action = () =>
      cleanupGuestStage({ name: 'agent-guard-fixture', directory, input, created }, () => {
        calls++;
        throw new Error('simulated daemon failure');
      });
    if (created)
      assert.throws(action, {
        message: 'CONTAINER_CLEANUP_FAILED',
        container: 'agent-guard-fixture',
      });
    else action();
    assert.equal(calls, created ? 1 : 0);
    assert.equal(existsSync(directory), false);
  }
});

test('missing pinned image or mismatched expected host cannot produce platform evidence', async () => {
  const missing = await verifyMcpIsolation({ image: 'node:latest' });
  assert.equal(missing.passed, false);
  assert.equal(missing.cleanup, true);
  assert.equal(missing.failure.code, 'PINNED_NODE_IMAGE_REQUIRED');
  const mismatched = await verifyMcpIsolation({
    image,
    expectedHost: 'not-a-platform',
  });
  assert.equal(mismatched.passed, false);
  assert.equal(mismatched.failure.code, 'EXPECTED_HOST_MISMATCH');
});

test('MCP isolation CLI accepts one explicit report path and rejects ambiguous options', () => {
  assert.deepEqual(parseOptions([]), {});
  assert.deepEqual(parseOptions(['--output', 'report.json']), {
    output: 'report.json',
  });
  for (const args of [
    ['--image', 'mutable'],
    ['--output'],
    ['--output', 'a', '--output', 'b'],
    ['--output', '--unknown'],
  ])
    assert.throws(() => parseOptions(args));
});

test(
  'real isolated MCP deployment enforces credential custody transport scope lifecycle and cleanup',
  {
    skip: !process.env.AGENT_GUARD_MCP_ISOLATION_IMAGE,
    timeout: 120000,
  },
  async () => {
    const report = await verifyMcpIsolation();
    assert.equal(report.passed, true, JSON.stringify(report));
    assert.equal(validateMcpIsolationReport(report), true);
    assert.equal(report.checks.length, REQUIRED_MCP_CHECKS.length);
    const serialized = JSON.stringify(report);
    assert(!serialized.includes('HOST_PRIVATE_'));
    assert(!serialized.includes('Bearer '));
  },
);
