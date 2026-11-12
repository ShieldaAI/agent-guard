import nodeTest from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, realpathSync, rmSync, writeFileSync, readFileSync, readdirSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createLedgerKeyring, readLedgerKeyringPolicy } from '../../../packages/executor/dist/ledger-maintenance.js';
import { normalizeLimits } from '../limits.mjs';
import { initializeRuntime, openRuntime, openMaintenance } from '../runtime.mjs';
import { previewBusinessHistory, applyBusinessHistory, lookupBusinessHistory } from '../retention.mjs';
import { manageBusinessCustody } from '../custody.mjs';
const test = (name, fn) => nodeTest(name, { skip: process.platform === 'win32' }, fn);
function fixture(t) {
  const root = realpathSync(mkdtempSync(join(tmpdir(), 'ops-custody-')));
  for (const name of ['data', 'witness', 'config', 'history', 'custody', 'custody-witness', 'offline', 'backups'])
    mkdirSync(join(root, name), { mode: 0o700 });
  const config = {
    limits: normalizeLimits(),
    ledgerDatabase: join(root, 'data', 'guard.sqlite'),
    backendDatabase: join(root, 'data', 'tickets.sqlite'),
    ledgerWitness: join(root, 'witness', 'guard.sqlite'),
    backendWitness: join(root, 'witness', 'tickets.sqlite'),
    keyringFile: join(root, 'config', 'keys.json'),
    historyDirectory: join(root, 'history'),
  };
  createLedgerKeyring({ keyringFile: config.keyringFile, keyId: 'initial' });
  initializeRuntime(config, [{ id: 'T-1', tenantId: 'acme', title: 'Private record', status: 'open' }]);
  const custody = {
    version: 1,
    custodyDatabase: join(root, 'custody', 'catalog.sqlite'),
    custodyWitness: join(root, 'custody-witness', 'anchor.sqlite'),
    custodyKeyringFile: join(root, 'offline', 'keys.json'),
    backupDirectory: join(root, 'backups'),
  };
  createLedgerKeyring({ keyringFile: custody.custodyKeyringFile, keyId: 'custody-initial', maxKeys: 64 });
  const custodyConfigFile = join(root, 'offline', 'custody.json');
  writeFileSync(custodyConfigFile, JSON.stringify(custody), { mode: 0o600 });
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const run = request => manageBusinessCustody(config, { custodyConfigFile, ...request });
  const apply = request => {
    const preview = run(request);
    return run({ ...request, apply: true, digest: preview.digest });
  };
  return { config, custody, custodyConfigFile, run, apply };
}
test('business custody preserves complete external history and exact receipts through backup, rotation, retirement and restore', async t => {
  const f = fixture(t),
    owner = { id: 'owner', tenantId: 'acme' };
  let runtime = openRuntime(f.config),
    request;
  try {
    request = (await runtime.workflow.propose(owner, { ticketId: 'T-1', status: 'resolved' })).request;
    await runtime.workflow.decide(owner, request.id, { digest: request.digest }, true);
  } finally {
    runtime.close();
  }
  const stores = openMaintenance(f.config);
  try {
    const review = previewBusinessHistory(stores, f.config, { tenantId: 'acme' });
    applyBusinessHistory(stores, f.config, { tenantId: 'acme', digest: review.digest });
  } finally {
    stores.close();
  }
  f.apply({ operation: 'enroll' });
  const first = f.apply({ operation: 'backup' });
  assert.equal(f.run({ operation: 'verify', backupId: first.backupId }).backupCount, 1);
  f.apply({ operation: 'rotate', keyId: 'second' });
  f.apply({ operation: 'retire', keyId: 'initial' });
  assert.equal(readLedgerKeyringPolicy({ keyringFile: f.config.keyringFile }).keyCount, 1);
  const current = f.apply({ operation: 'backup' }),
    history = readdirSync(f.config.historyDirectory).filter(name => !name.startsWith('.'));
  assert.equal(history.length, 1);
  const historical = readFileSync(join(f.config.historyDirectory, history[0]));
  rmSync(join(f.config.historyDirectory, history[0]));
  writeFileSync(f.config.backendDatabase, Buffer.from('corrupt source'));
  f.apply({ operation: 'restore', backupId: current.backupId });
  assert.deepEqual(readFileSync(join(f.config.historyDirectory, history[0])), historical);
  const recovered = openMaintenance(f.config);
  try {
    const found = lookupBusinessHistory(recovered, f.config, { tenantId: 'acme', requestId: request.id });
    assert.equal(found.receipt.status, 'resolved');
  } finally {
    recovered.close();
  }
  runtime = openRuntime(f.config);
  try {
    assert.equal(runtime.workflow.ticket('T-1', 'acme').status, 'resolved');
  } finally {
    runtime.close();
  }
  assert.equal(f.run({ operation: 'verify', backupId: first.backupId }).backupCount, 2);
});

test('history corruption or missing closure blocks backup and retirement without altering active ring', async t => {
  const f = fixture(t),
    owner = { id: 'owner', tenantId: 'acme' },
    runtime = openRuntime(f.config);
  try {
    const req = (await runtime.workflow.propose(owner, { ticketId: 'T-1', status: 'resolved' })).request;
    await runtime.workflow.decide(owner, req.id, { digest: req.digest }, true);
  } finally {
    runtime.close();
  }
  const stores = openMaintenance(f.config);
  try {
    const review = previewBusinessHistory(stores, f.config, { tenantId: 'acme' });
    applyBusinessHistory(stores, f.config, { tenantId: 'acme', digest: review.digest });
  } finally {
    stores.close();
  }
  f.apply({ operation: 'enroll' });
  f.apply({ operation: 'rotate', keyId: 'second' });
  const history = readdirSync(f.config.historyDirectory).filter(name => !name.startsWith('.'))[0];
  writeFileSync(join(f.config.historyDirectory, history), Buffer.from('broken history'));
  assert.throws(() => f.run({ operation: 'backup' }));
  assert.throws(() => f.run({ operation: 'retire', keyId: 'initial' }));
  assert.equal(readLedgerKeyringPolicy({ keyringFile: f.config.keyringFile }).keyCount, 2);
});

test('process loss while restoring a history file rebuilds its partial stage and preserves exact receipt', async t => {
  const f = fixture(t),
    owner = { id: 'owner', tenantId: 'acme' },
    runtime = openRuntime(f.config);
  let request;
  try {
    request = (await runtime.workflow.propose(owner, { ticketId: 'T-1', status: 'resolved' })).request;
    await runtime.workflow.decide(owner, request.id, { digest: request.digest }, true);
  } finally {
    runtime.close();
  }
  const stores = openMaintenance(f.config);
  try {
    const review = previewBusinessHistory(stores, f.config, { tenantId: 'acme' });
    applyBusinessHistory(stores, f.config, { tenantId: 'acme', digest: review.digest });
  } finally {
    stores.close();
  }
  f.apply({ operation: 'enroll' });
  const backup = f.apply({ operation: 'backup' }),
    name = readdirSync(f.config.historyDirectory).filter(n => !n.startsWith('.'))[0];
  rmSync(join(f.config.historyDirectory, name));
  const script = `import fs from 'node:fs';import {syncBuiltinESMExports} from 'node:module';import {manageBusinessCustody} from ${JSON.stringify(new URL('../custody.mjs', import.meta.url).href)};const config=${JSON.stringify(f.config)},options={custodyConfigFile:${JSON.stringify(f.custodyConfigFile)},operation:'restore',backupId:${JSON.stringify(backup.backupId)}};const preview=manageBusinessCustody(config,options);const open=fs.openSync,write=fs.writeSync;let stage;fs.openSync=function(p,...a){const fd=open.call(this,p,...a);if(String(p).includes('.custody-history-')&&(a[0]&fs.constants.O_WRONLY))stage=fd;return fd;};fs.writeSync=function(fd,b,o,n,...a){if(fd===stage){write.call(this,fd,b,o,Math.min(16,n),...a);process.kill(process.pid,'SIGKILL');}return write.call(this,fd,b,o,n,...a);};syncBuiltinESMExports();manageBusinessCustody(config,{...options,apply:true,digest:preview.digest});`;
  const child = spawnSync(process.execPath, ['--input-type=module', '-e', script], { encoding: 'utf8' });
  assert.equal(child.signal, 'SIGKILL', child.stderr);
  assert.equal(f.apply({ operation: 'recover' }).pending, false);
  const recovered = openMaintenance(f.config);
  try {
    assert.equal(
      lookupBusinessHistory(recovered, f.config, { tenantId: 'acme', requestId: request.id }).receipt.status,
      'resolved',
    );
  } finally {
    recovered.close();
  }
  // The executor discards an incomplete stage and rebuilds it from the backup: the history
  // file is back and no staged or partial file is left behind.
  const names = readdirSync(f.config.historyDirectory);
  assert.ok(names.includes(name));
  assert.equal(
    names.some(n => n.startsWith('.custody-history-') || n.includes('.partial-')),
    false,
  );
});
