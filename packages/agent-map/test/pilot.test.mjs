import assert from 'node:assert/strict';
import test from 'node:test';
import { spawn } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { chmod, mkdtemp, mkdir, writeFile, rm, symlink } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createInterface } from 'node:readline';
import { startPilotHost, readPilotConfig } from '../../../examples/cartography-pilot.mjs';

const token = prefix => `${prefix}.${randomBytes(32).toString('base64url')}`;
async function configuration(t) {
  const stateDirectory = await mkdtemp(join(tmpdir(), 'agent-guard-pilot-'));
  await chmod(stateDirectory, 0o700); t.after(() => rm(stateDirectory, { recursive: true, force: true }));
  return { stateDirectory, observerToken: token('agi_v1'),
    referenceTokens: { blue: token('agm_v1'), red: token('agm_v1'), beta: token('agm_v1') },
    neo4j: { uri: 'bolt://127.0.0.1:1', username: 'reader', password: 'synthetic-database-password' } };
}
test('live pilot observer exports scoped host inventory and stopping reference/observer cannot stop admission', async t => {
  const config = await configuration(t), host = await startPilotHost(config); t.after(() => host.close());
  const ready = host.ready;
  assert.equal(ready.sources.length, 2); assert.equal(new Set(ready.sources.map(source => source.inventoryInstanceId)).size, 1);
  const collected = await fetch(ready.observerEndpoint, { method: 'POST', headers: { Authorization: `Bearer ${config.observerToken}`, 'Content-Type': 'application/json' }, body: '{"tenantId":"alpha"}' });
  assert.equal(collected.status, 200); const snapshot = await collected.json();
  assert.equal(snapshot.profile, 'host'); assert.deepEqual(snapshot.tasks.map(task => task.id).sort(), ['pilot-blue-task', 'pilot-red-task']);
  assert.deepEqual(snapshot.manifest.agents.map(agent => agent.teamId).sort(), ['blue', 'red']);
  assert.ok(!JSON.stringify(snapshot).includes('report-blue'));
  const unauthenticated = await fetch(ready.referenceUrl + '/v1/query', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{"operation":"list_agents","args":{}}' });
  assert.equal(unauthenticated.status, 401);
  const first = await host.command({ command: 'execute', task: 'blue' }); assert.equal(first.ok, true); assert.equal(first.calls.blue, 1);
  const denied = await host.command({ command: 'execute', task: 'red', resource: 'blue' });
  assert.equal(denied.ok, false); assert.equal(denied.code, 'GRANT_DENIED'); assert.equal(denied.executions, 1);
  const foreign = await host.command({ command: 'execute', task: 'blue', resource: 'beta' }); assert.equal(foreign.ok, false); assert.equal(foreign.code, 'TENANT_DENIED'); assert.equal(foreign.executions, 1);
  await host.command({ command: 'stop-reference' }); await host.command({ command: 'stop-observer' });
  const second = await host.command({ command: 'execute', task: 'blue' });
  assert.equal(second.ok, true); assert.equal(second.calls.blue, 2); assert.equal(second.executions, 2);
  assert.equal(second.observerRunning, false); assert.equal(second.referenceRunning, false);
  assert.equal(second.inventoryInstanceId, first.inventoryInstanceId);
  assert.ok(second.ledgerRevision > first.ledgerRevision);
  const renewed = await host.command({ command: 'start-reference', neo4j: { ...config.neo4j, uri: 'bolt://127.0.0.1:2' } }); assert.equal(renewed.ok, true); assert.match(renewed.referenceUrl, /^http:\/\/127\.0\.0\.1:/);
  assert.equal((await host.command({ command: 'start-reference', neo4j: config.neo4j })).ok, false);
  await host.command({ command: 'revoke', task: 'blue' });
  const revoked = await host.command({ command: 'execute', task: 'blue' }); assert.equal(revoked.ok, false); assert.equal(revoked.code, 'TASK_REVOKED'); assert.equal(revoked.executions, 2);
  for (const secret of [config.observerToken, ...Object.values(config.referenceTokens), config.neo4j.password, 'pilot-private-argument-canary']) assert.ok(!JSON.stringify([ready, first, second, snapshot]).includes(secret));
});
test('pilot host rejects unknown settings, duplicate credentials and existing authority directories', async t => {
  const config = await configuration(t);
  await assert.rejects(startPilotHost({ ...config, host: '0.0.0.0' }), /PILOT_CONFIG_INVALID/);
  await assert.rejects(startPilotHost({ ...config, referenceTokens: { ...config.referenceTokens, red: config.referenceTokens.blue } }), /PILOT_CONFIG_INVALID/);
  await mkdir(join(config.stateDirectory, 'synthetic-authority'), { mode: 0o700 });
  await assert.rejects(startPilotHost(config), { code: 'EEXIST' });
});
test('private pilot configuration rejects duplicate JSON, oversize content, links and public permissions', async t => {
  const config = await configuration(t), path = join(config.stateDirectory, 'config.json');
  await writeFile(path, JSON.stringify(config), { mode: 0o600 });
  if (process.platform === 'win32') { await assert.rejects(readPilotConfig(path), /PILOT_PLATFORM_UNSUPPORTED/); return; }
  assert.equal((await readPilotConfig(path)).observerToken, config.observerToken);
  await writeFile(path, '{"x":1,"\\u0078":2}'); await assert.rejects(readPilotConfig(path), /PILOT_CONFIG_INVALID/);
  await writeFile(path, ' '.repeat(65_537)); await assert.rejects(readPilotConfig(path), /PILOT_CONFIG_INVALID/);
  await writeFile(path, JSON.stringify(config));
  if (process.platform !== 'win32') {
    await symlink(path, join(config.stateDirectory, 'link.json'));
    await assert.rejects(readPilotConfig(join(config.stateDirectory, 'link.json')), /PILOT_CONFIG_INVALID/);
    await chmod(path, 0o644); await assert.rejects(readPilotConfig(path), /PILOT_CONFIG_INVALID/);
  }
});
test('pilot stdin lifecycle emits safe readiness/results, never secret values', async t => {
  const config = await configuration(t), path = join(config.stateDirectory, 'config.json');
  await writeFile(path, JSON.stringify(config), { mode: 0o600 });
  const child = spawn(process.execPath, [fileURLToPath(new URL('../../../examples/cartography-pilot.mjs', import.meta.url)), '--config', path], { stdio: ['pipe', 'pipe', 'pipe'] });
  t.after(() => child.kill('SIGKILL'));
  const lines = createInterface({ input: child.stdout })[Symbol.asyncIterator](); let errors = '';
  child.stderr.on('data', chunk => { errors += chunk; });
  const exit = new Promise(resolve => child.once('exit', (code, signal) => resolve({ code, signal })));
  if (process.platform === 'win32') { assert.deepEqual(await exit, { code: 1, signal: null }); assert.equal(errors, 'PILOT_HOST_FAILED\n'); return; }
  const next = async () => {
    let timer; try { return await Promise.race([lines.next(), new Promise((_, reject) => { timer = setTimeout(() => reject(new Error('bounded child response missing')), 5000); })]); }
    finally { clearTimeout(timer); }
  };
  const ready = JSON.parse((await next()).value); assert.equal(ready.event, 'ready');
  child.stdin.write('{"command":"execute","task":"blue"}\n'); const first = JSON.parse((await next()).value); assert.equal(first.ok, true);
  child.stdin.write('{"command":"status","arbitrary":"not-allowed"}\n'); const denied = JSON.parse((await next()).value); assert.deepEqual(denied, { ok: false, code: 'PILOT_REQUEST_INVALID' });
  child.stdin.write('{"command":"close"}\n'); assert.deepEqual(JSON.parse((await next()).value), { ok: true, closed: true });
  child.stdin.end(); assert.deepEqual(await exit, { code: 0, signal: null });
  for (const secret of [config.observerToken, ...Object.values(config.referenceTokens), config.neo4j.password]) assert.ok(!JSON.stringify([ready, first, errors]).includes(secret));
  assert.ok(!errors.includes('PILOT_HOST_FAILED'));
});
test('oversized private control input shuts the pilot down without reflecting request contents', async t => {
  const config = await configuration(t), path = join(config.stateDirectory, 'config.json');
  await writeFile(path, JSON.stringify(config), { mode: 0o600 });
  const child = spawn(process.execPath, [fileURLToPath(new URL('../../../examples/cartography-pilot.mjs', import.meta.url)), '--config', path], { stdio: ['pipe', 'pipe', 'pipe'] });
  t.after(() => child.kill('SIGKILL'));
  let output = '', errors = ''; child.stdout.on('data', chunk => { output += chunk; }); child.stderr.on('data', chunk => { errors += chunk; });
  const exit = new Promise(resolve => child.once('exit', (code, signal) => resolve({ code, signal })));
  if (process.platform !== 'win32') {
    await new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error('pilot startup deadline')), 5000);
      child.stdout.once('data', () => { clearTimeout(timer); resolve(); });
    });
    child.stdin.write('private-control-canary'.repeat(250));
  }
  let timer;
  try {
    const result = await Promise.race([exit, new Promise((_, reject) => { timer = setTimeout(() => reject(new Error('pilot shutdown deadline')), 5000); })]);
    assert.deepEqual(result, { code: 1, signal: null });
  } finally { clearTimeout(timer); }
  assert.equal(errors, 'PILOT_HOST_FAILED\n'); assert.ok(!output.includes('private-control-canary'));
});
