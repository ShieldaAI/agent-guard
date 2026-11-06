import test from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { makeStdio, safeGuestState } from './verify-mcp-isolation.mjs';

function fixture(t, { writeError, spawnError } = {}) {
  const child = new EventEmitter(), writes = [], signals = []; let now = 0;
  child.pid = 123;
  child.stdin = new EventEmitter(); child.stdout = new EventEmitter(); child.stderr = new EventEmitter();
  child.stdin.write = (line, callback) => { writes.push(line); callback(writeError); };
  child.stdin.end = () => queueMicrotask(() => child.emit('close', 0, null));
  child.kill = signal => { signals.push(signal); queueMicrotask(() => child.emit('close', null, signal)); };
  const transport = makeStdio('synthetic-owned-container', 'PRIVATE-CANARY', {
    clock: () => now,
    spawnProcess(command, args, options) {
      assert.equal(command, 'docker'); assert.deepEqual(args, ['exec', '-i', 'synthetic-owned-container', 'node', '/input/guest.mjs']);
      assert.equal(options.shell, false); assert.deepEqual(options.stdio, ['pipe', 'pipe', 'pipe']);
      if (spawnError) throw spawnError;
      return child;
    },
  });
  t.after(() => transport.close());
  return { child, transport, writes, signals, at: value => { now = value; } };
}

test('stdio diagnostics preserve actual messages and request writes while retaining only fixed scalar observations', async t => {
  const f = fixture(t), received = [];
  f.transport.onmessage = message => received.push(message);
  await f.transport.start(); f.at(2); f.child.emit('spawn');
  f.at(5); const initialize = { jsonrpc: '2.0', id: 71, method: 'initialize', params: { private: 'PRIVATE-PARAM' } };
  await f.transport.send(initialize);
  assert.equal(f.writes[0], JSON.stringify(initialize) + '\n');
  f.at(20); const response = { jsonrpc: '2.0', id: 71, result: { private: 'PRIVATE-RESULT' } };
  f.child.stdout.emit('data', Buffer.from(JSON.stringify(response) + '\n'));
  assert.deepEqual(received, [response]);
  f.at(25); await f.transport.send({ jsonrpc: '2.0', id: 72, method: 'tools/list' });
  f.at(30); f.child.stdout.emit('data', Buffer.from('{"jsonrpc":"2.0","id":72,"result":{"tools":[]}}\n'));
  const report = f.transport.diagnostics();
  assert.equal(report.spawnedMs, 2); assert.equal(report.firstStdoutMs, 20);
  assert.deepEqual(report.requests, [
    { kind: 'initialize', sentMs: 5, writeCompletedMs: 5, responseMs: 20, unansweredMs: null },
    { kind: 'tools-list', sentMs: 25, writeCompletedMs: 25, responseMs: 30, unansweredMs: null },
  ]);
  assert.equal(report.reason, 'RESPONSE_OBSERVED'); assert.equal(report.receivedFrames, 2);
  assert.equal(JSON.stringify(report).includes('PRIVATE'), false);
  report.requests[0].sentMs = 999; assert.equal(f.transport.diagnostics().requests[0].sentMs, 5);
  // An untracked ID is still sent unchanged and never enters the diagnostic report.
  await f.transport.send({ jsonrpc: '2.0', id: 'PRIVATE-ID', method: 'initialize' });
  assert.equal(JSON.stringify(f.transport.diagnostics()).includes('PRIVATE'), false);
});

test('unanswered request deadline uses original close time and does not misclassify later cleanup delay', async t => {
  for (const closeAt of [1499, 1500, 1501]) {
    const f = fixture(t); await f.transport.start();
    await f.transport.send({ jsonrpc: '2.0', id: 0, method: 'initialize' });
    f.at(closeAt); await f.transport.close(); f.at(60_000);
    const report = f.transport.diagnostics();
    assert.equal(report.requestTimeoutMs, 1500); assert.equal(report.requests[0].unansweredMs, closeAt);
    assert.equal(report.reason, closeAt >= 1500 ? 'RESPONSE_NOT_OBSERVED_BY_DEADLINE' : 'CONNECTION_FAILURE_UNCLASSIFIED');
    assert.equal(report.closeRequestedMs, closeAt); assert.equal(report.closedMs, closeAt);
    assert.deepEqual(f.signals, []);
  }
});

test('stdio diagnostics distinguish spawn, write, stream, framing and early exit without reflecting errors', async t => {
  for (const kind of ['spawn', 'write', 'input', 'output', 'stderr', 'frame', 'delivery', 'exit']) {
    const privateError = new Error('PRIVATE-ERROR /private/path Bearer PRIVATE-TOKEN');
    const f = fixture(t, { ...(kind === 'spawn' ? { spawnError: privateError } : {}), ...(kind === 'write' ? { writeError: privateError } : {}) });
    let reason;
    if (kind === 'spawn') { await assert.rejects(f.transport.start(), error => error === privateError); reason = 'STDIO_SPAWN_ERROR'; }
    else {
      await f.transport.start();
      if (kind === 'write') { await assert.rejects(f.transport.send({ id: 0, method: 'initialize' }), /ISOLATED_TRANSPORT_FAILED/); reason = 'STDIO_WRITE_FAILED'; }
      else if (['input', 'output', 'stderr'].includes(kind)) {
        f.child[kind === 'input' ? 'stdin' : kind === 'output' ? 'stdout' : 'stderr'].emit('error', privateError);
        reason = 'STDIO_' + kind.toUpperCase() + '_ERROR';
      } else if (kind === 'frame') { f.child.stdout.emit('data', Buffer.from('PRIVATE-INVALID-JSON\n')); reason = 'STDIO_FRAME_INVALID'; }
      else if (kind === 'delivery') { f.transport.onmessage = () => { throw privateError; }; f.child.stdout.emit('data', Buffer.from('{}\n')); reason = 'STDIO_DELIVERY_FAILED'; }
      else { f.child.emit('close', 137, 'PRIVATE-SIGNAL'); reason = 'STDIO_UNEXPECTED_CLOSE'; }
    }
    const report = f.transport.diagnostics(); assert.equal(report.reason, reason);
    assert.equal(JSON.stringify(report).includes('PRIVATE'), false);
    if (kind === 'exit') { assert.equal(report.exitCode, 137); assert.equal(report.exitSignal, null); }
    if (['input', 'output', 'stderr', 'frame', 'delivery'].includes(kind)) assert.deepEqual(f.signals, ['SIGKILL']);
  }
});

test('existing stdout frame and combined output limits remain exact with diagnostics enabled', async t => {
  const f = fixture(t); await f.transport.start(); let received = 0;
  f.transport.onmessage = () => received++;
  const frame = Buffer.from(JSON.stringify('x'.repeat(65533)) + '\n'); assert.equal(frame.length, 65536);
  f.child.stdout.emit('data', frame); assert.equal(received, 1); assert.equal(f.transport.diagnostics().failure, null);
  f.child.stderr.emit('data', Buffer.alloc(262144 - 65536)); assert.equal(f.transport.diagnostics().failure, null);
  f.child.stderr.emit('data', Buffer.from('x')); assert.equal(f.transport.diagnostics().failure, 'STDIO_OUTPUT_LIMIT');
  const g = fixture(t); await g.transport.start(); g.child.stdout.emit('data', Buffer.alloc(65537));
  assert.equal(g.transport.diagnostics().failure, 'STDIO_FRAME_LIMIT');
});

test('guest-state diagnostics require exact created identity and expose no environment or runtime error text', () => {
  const id = 'a'.repeat(64), name = 'synthetic-owned';
  const value = { Id: id, Name: '/' + name, Config: { Labels: { 'io.shielda.agent-guard.owner-pid': String(process.pid) }, Env: ['PRIVATE-ENV'] },
    State: { Running: false, OOMKilled: true, ExitCode: 137, Error: 'PRIVATE-ERROR' } };
  assert.deepEqual(safeGuestState(value, name, id), { available: true, running: false, oomKilled: true, exitCode: 137 });
  for (const change of [v => { v.Id = 'b'.repeat(64); }, v => { v.Name = '/other'; }, v => { v.Config.Labels = null; },
    v => { v.Config = null; }, v => { v.State = null; }, v => { v.State.ExitCode = 'PRIVATE'; }]) {
    const changed = structuredClone(value); change(changed); assert.deepEqual(safeGuestState(changed, name, id), { available: false });
  }
  for (const malformed of [null, false, 1, 'PRIVATE']) assert.deepEqual(safeGuestState(malformed, name, id), { available: false });
});
