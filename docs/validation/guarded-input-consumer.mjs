// Copied into a fresh offline npm consumer by package-guarded-input-candidate.py.
import assert from 'node:assert/strict';
import childProcess from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { syncBuiltinESMExports } from 'node:module';
import { tmpdir } from 'node:os';
import { join, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { ArtifactBroker, createSandboxTool, DurableExecutor } from '@shieldaai/agent-guard-executor';

const image = process.argv[2];
assert.match(image, /^.+@sha256:[a-f0-9]{64}$/);
const fixture = JSON.parse(readFileSync(new URL('./packed-build-attestation.json', import.meta.url), 'utf8'));
const consumer = realpathSync(fileURLToPath(new URL('.', import.meta.url)));
const names = ['agent-guard', 'agent-guard-mcp', 'agent-guard-scenarios', 'agent-guard-executor', 'agent-map'];
for (const name of names) {
  const pkg = `@shieldaai/${name}`;
  const entry = realpathSync(fileURLToPath(import.meta.resolve(pkg)));
  assert.ok(entry.startsWith(join(consumer, 'node_modules', pkg) + sep));
  assert.ok(Object.keys(await import(pkg)).length > 0);
}
const original = Buffer.from('fixture');
const scratch = realpathSync(mkdtempSync(join(tmpdir(), 'guarded-input-consumer-')));
const spawn = childProcess.spawn;
let dockerCalls = 0;
childProcess.spawn = function(command, ...args) {
  if (command === 'docker') dockerCalls++;
  return Reflect.apply(spawn, this, [command, ...args]);
};
syncBuiltinESMExports();

async function probeStaging(profile) {
  const workspace = join(scratch, profile);
  mkdirSync(workspace, { mode: 0o700 });
  const selected = join(workspace, fixture.rule.path);
  const unselected = join(scratch, `outside-${profile}`);
  writeFileSync(unselected, original);
  writeFileSync(selected, original);
  const host = new DurableExecutor({ database: ':memory:', encryptionKey: randomBytes(32) });
  const attested = profile === 'attested';
  const broker = new ArtifactBroker({ key: randomBytes(32), keyId: 'probe-host',
    ...(attested ? { buildPolicy: { artifacts: [fixture.rule] } } : {}) });
  try {
    const inputReceipts = attested ? [broker.admitBuildArtifact({ content: original, path: fixture.rule.path,
      tenantId: fixture.rule.tenantId, attestation: fixture.attestation })] : [];
    let results = 0;
    const definition = createSandboxTool({ name: 'shell', executor: host, broker, workspace,
      profile: { image, timeoutMs: 30_000 }, tenantId: fixture.rule.tenantId, resourceId: 'workspace',
      origin: 'consumer-fixture', inputFiles: [fixture.rule.path], inputClassification: 'public', inputReceipts,
      onResult(output) { assert.equal(output.result.stdout, original.toString()); results++; return 'stored'; } });
    host.approveTool('shell', host.registerTool(definition));
    // Instrument the public broker boundary after the adapter's approval checks. Forward the real call.
    const stage = broker.runGovernedSandbox.bind(broker);
    let casesEntered = 0, variant;
    broker.runGovernedSandbox = (...args) => {
      casesEntered++;
      if (variant === 'swapped') writeFileSync(selected, 'swapped');
      if (variant === 'symlink') { rmSync(selected); symlinkSync(unselected, selected); }
      return stage(...args);
    };
    const observations = {};
    for (variant of ['swapped', 'symlink', 'unchanged']) {
      rmSync(selected); writeFileSync(selected, original);
      const id = `${profile}-${variant}`;
      const spec = { id, tenantId: fixture.rule.tenantId, principalId: 'probe-host',
        grants: [{ tool: 'shell', resources: ['workspace'] }],
        budget: { maxCalls: 1, maxConcurrent: 1, maxCost: 0, deadline: Date.now() + 120_000 } };
      if (attested) broker.createTaskFromArtifacts(host, spec, [
        { envelope: inputReceipts[0], contentBase64: original.toString('base64') }]);
      else host.createTask(spec);
      const action = await host.prepare(id, { tool: 'shell', args: { command: ['/bin/cat', fixture.rule.path] } });
      const approvalId = host.approve(action.id, { approverId: 'reviewer', expiresAt: Date.now() + 60_000 });
      const before = dockerCalls, priorStageCalls = casesEntered;
      const attempt = host.execute(id, action.id, { approvalId });
      if (variant === 'unchanged') {
        const value = await attempt;
        assert.equal(value.exitCode, 0); assert.equal(value.resultId, 'stored');
        assert.equal(value.stdout.text, original.toString()); assert.equal(results, 1);
        assert.ok(dockerCalls > before);
        observations[variant] = { guestExit: value.exitCode, approvedBytesReturned: true, results };
      } else {
        const code = variant === 'swapped' ? 'TOOL_CHANGED' : 'TOOL_FAILED';
        await assert.rejects(attempt, { code });
        assert.equal(dockerCalls, before); assert.equal(results, 0);
        observations[variant] = { code, dockerCalls: dockerCalls - before, results };
      }
      assert.equal(casesEntered - priorStageCalls, 1);
    }
    return observations;
  } finally { broker.close(); host.close(); }
}

async function probeWitness() {
  const data = join(scratch, 'data'), control = join(scratch, 'control');
  for (const directory of [data, control]) mkdirSync(directory, { mode: 0o700 });
  const database = join(data, 'ledger.sqlite'), path = join(control, 'witness.sqlite');
  const options = { database, encryptionKey: randomBytes(32), clock: () => 1000 };
  const open = (mode) => new DurableExecutor({ ...options, rollbackWitness: { mode, path } });
  let effects = 0;
  const register = (host) => host.approveTool('write', host.registerTool({ name: 'write', description: 'count one write',
    maxCost: 1, requiresApproval: true, resolve: () => ({ tenantId: 'tenant', resourceId: 'fixture' }),
    execute: () => ({ value: ++effects, actualCost: 1 }) }));
  let host = open('create'), bearer;
  try {
    register(host);
    bearer = host.createTask({ id: 'task', tenantId: 'tenant', principalId: 'probe-host',
      grants: [{ tool: 'write', resources: ['fixture'] }],
      budget: { maxCalls: 1, maxConcurrent: 1, maxCost: 1, deadline: 2000 } });
  } finally { host.close(); }
  const historical = readFileSync(database);
  host = open('resume');
  try {
    register(host);
    const id = host.authenticate(bearer.token), action = await host.prepare(id, { tool: 'write', args: null });
    const approvalId = host.approve(action.id, { approverId: 'reviewer', expiresAt: 1500 });
    assert.equal(await host.execute(id, action.id, { approvalId }), 1); host.revokeTask(id);
  } finally { host.close(); }
  const latest = readFileSync(database), reference = readFileSync(path);
  writeFileSync(database, historical);
  assert.throws(() => open('resume'), { code: 'STORE_WITNESS_UNAVAILABLE' });
  assert.throws(() => new DurableExecutor(options), { code: 'STORE_UNAVAILABLE' });
  assert.deepEqual(readFileSync(path), reference);
  writeFileSync(database, latest); host = open('resume');
  try {
    assert.throws(() => host.authenticate(bearer.token), { code: 'UNAUTHENTICATED' });
    const spent = host.snapshot('task').spent;
    assert.equal(spent, 1); assert.equal(effects, 1);
    return { restoredHistoricalLedger: 'STORE_WITNESS_UNAVAILABLE', unfencedReopen: 'STORE_UNAVAILABLE',
      currentWitnessUnchanged: true, revokedCredential: 'UNAUTHENTICATED', spent, effects };
  } finally { host.close(); }
}

try {
  const raw = await probeStaging('raw'), attested = await probeStaging('attested');
  const witness = await probeWitness();
  console.log(JSON.stringify({ importedInstalledPackages: names.length, host: process.platform,
    arch: process.arch, node: process.version, shellImage: image, stagedInput: { raw, attested }, witness }));
} finally {
  childProcess.spawn = spawn; syncBuiltinESMExports(); rmSync(scratch, { recursive: true, force: true });
}
