import test from 'node:test';
import assert from 'node:assert/strict';
import childProcess from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import { syncBuiltinESMExports } from 'node:module';
import { readWindowsWorkspaceInput as read } from '../dist/workspace-input-windows.js';

const selectedRoot = 'C:\\private-workspace';
const selectedName = 'private-selected.bin';
const scratch = 'C:\\Users\\host\\AppData\\Local\\Temp\\agent-guard-input-fixture';
const privateDiagnostic = 'private-compiler-path-and-selected-content';
function frame(bytes = Buffer.from('approved bytes')) {
  const header = Buffer.alloc(8);
  header.writeUInt32LE(0x31444741);
  header.writeUInt32LE(bytes.length, 4);
  return Buffer.concat([header, bytes]);
}

function simulate(t, result) {
  const platform = Object.getOwnPropertyDescriptor(process, 'platform');
  const systemRoot = process.env.SystemRoot;
  Object.defineProperty(process, 'platform', { ...platform, value: 'win32' });
  process.env.SystemRoot = 'C:\\Windows';
  const cleaned = [], calls = [];
  t.mock.method(os, 'userInfo', () => ({ homedir: 'C:\\Users\\host' }));
  t.mock.method(fs, 'mkdtempSync', () => scratch);
  t.mock.method(fs, 'rmSync', (path, options) => cleaned.push({ path, options }));
  t.mock.method(childProcess, 'spawnSync', (...args) => { calls.push(args); return result; });
  syncBuiltinESMExports();
  t.after(() => {
    t.mock.restoreAll();
    syncBuiltinESMExports();
    Object.defineProperty(process, 'platform', platform);
    if (systemRoot === undefined) delete process.env.SystemRoot;
    else process.env.SystemRoot = systemRoot;
  });
  return { cleaned, calls };
}

for (const [name, result, reason, stage] of [
  ['timeout before helper startup', { error: Object.assign(new Error(privateDiagnostic), { code: 'ETIMEDOUT' }), status: null, stdout: Buffer.alloc(0) }, 'timeout', 'not-started'],
  ['timeout during compilation', { error: Object.assign(new Error(privateDiagnostic), { code: 'ETIMEDOUT' }), status: null, stdout: Buffer.from([0x41]) }, 'timeout', 'compiling'],
  ['timeout during native copy', { error: Object.assign(new Error(privateDiagnostic), { code: 'ETIMEDOUT' }), status: null, stdout: Buffer.from([0x41, 0x47]) }, 'timeout', 'copying'],
  ['launch failure', { error: Object.assign(new Error(privateDiagnostic), { code: 'ENOENT' }), status: null, stdout: null }, 'spawn', 'not-started'],
  ['native refusal', { status: 1, stdout: Buffer.from([0x41, 0x47]) }, 'exit', 'copying'],
  ['unexpected compiler output', { status: 0, stdout: Buffer.from(privateDiagnostic) }, 'protocol', 'not-started'],
  ['missing completed frame', { status: 0, stdout: Buffer.from([0x41, 0x47]) }, 'protocol', 'copying'],
  ['oversized output frame', { status: 0, stdout: frame(Buffer.alloc(33)) }, 'protocol', 'complete'],
  ['trailing output bytes', { status: 0, stdout: Buffer.concat([frame(), Buffer.from('extra')]) }, 'protocol', 'complete'],
]) {
  test(`Windows workspace diagnostic is fixed and fail-closed: ${name}`, t => {
    const { cleaned, calls } = simulate(t, { stderr: Buffer.from(privateDiagnostic), ...result });
    let returned = false;
    assert.throws(() => { read(selectedRoot, selectedName, 32); returned = true; }, error => {
      assert.equal(error.code, 'WORKSPACE_INPUT_UNAVAILABLE');
      assert.equal(error.reason, reason);
      assert.equal(error.stage, stage);
      for (const secret of [selectedRoot, selectedName, scratch, privateDiagnostic]) {
        assert.equal(`${error.message} ${JSON.stringify(error)}`.includes(secret), false);
      }
      assert.equal(error.cause, undefined);
      return true;
    });
    assert.equal(returned, false);
    assert.equal(calls.length, 1, 'no subprocess retry');
    assert.equal(calls[0][2].timeout, 30_000);
    assert.equal(calls[0][2].maxBuffer, 4096);
    assert.deepEqual(cleaned, [{ path: scratch, options: { recursive: true, force: true } }]);
  });
}

test('Windows helper returns only a complete bounded frame from the trusted fixed command', t => {
  const bytes = Buffer.from([0, 255, 10, 13, 26]);
  const { cleaned, calls } = simulate(t, { status: 0, stdout: frame(bytes), stderr: Buffer.alloc(0) });
  assert.deepEqual(read(selectedRoot, selectedName, bytes.length), bytes);
  const [executable, args, options] = calls[0];
  assert.equal(executable, 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe');
  assert.deepEqual(args.slice(0, 4), ['-NoLogo', '-NoProfile', '-NonInteractive', '-EncodedCommand']);
  const program = Buffer.from(args[4], 'base64').toString('utf16le');
  assert.equal(program.includes(selectedRoot), false);
  assert.equal(program.includes(selectedName), false);
  assert.match(program, /OBJ_DONT_REPARSE/);
  assert.match(program, /ShareRead, options/);
  assert.equal(options.env.TEMP, scratch);
  assert.equal(options.env.TMP, scratch);
  assert.equal(options.env.PATH, 'C:\\Windows\\System32');
  assert.equal(options.timeout, 30_000);
  assert.equal(options.maxBuffer, 4096);
  assert.equal(cleaned.length, 1);
});

test('Windows exact-limit frame keeps the existing aggregate output allowance', t => {
  const bytes = Buffer.alloc(8192, 255);
  const output = frame(bytes);
  const { calls } = simulate(t, { status: 0, stdout: output, stderr: Buffer.alloc(0) });
  assert.deepEqual(read(selectedRoot, selectedName, bytes.length), bytes);
  assert.equal(calls[0][2].maxBuffer, bytes.length + 8);
  assert.equal(output.length, calls[0][2].maxBuffer);
});

test('Windows cleanup failure retains the completed stage without exposing private errors or returning bytes', t => {
  const { calls } = simulate(t, { status: 0, stdout: frame(), stderr: Buffer.alloc(0) });
  t.mock.method(fs, 'rmSync', () => { throw new Error(`${scratch}: ${privateDiagnostic}`); });
  syncBuiltinESMExports();
  assert.throws(() => read(selectedRoot, selectedName, 32), error => {
    assert.equal(error.code, 'WORKSPACE_INPUT_UNAVAILABLE');
    assert.equal(error.reason, 'cleanup');
    assert.equal(error.stage, 'complete');
    assert.equal(error.cause, undefined);
    for (const secret of [selectedRoot, selectedName, scratch, privateDiagnostic]) {
      assert.equal(`${error.message} ${JSON.stringify(error)}`.includes(secret), false);
    }
    return true;
  });
  assert.equal(calls.length, 1);
});
