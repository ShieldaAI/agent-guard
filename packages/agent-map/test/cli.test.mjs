import assert from 'node:assert/strict';
import test from 'node:test';
import { spawn, spawnSync } from 'node:child_process';
import { constants } from 'node:fs';
import { mkdtemp, writeFile, symlink, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createMapToken } from '../dist/index.js';
import { runMapCli } from '../dist/cli.js';

const cli = fileURLToPath(new URL('../dist/cli.js', import.meta.url));
const supported = typeof constants.O_NONBLOCK === 'number';
const onSupportedHost = name => supported ? name : `${name}: rejects unsupported nonblocking opens`;
async function unsupportedHost() {
  if (supported) return false;
  // Assert rejection before opening a path, rather than silently skipping the
  // POSIX-only runtime cases in the native Windows CI job.
  await assert.rejects(runMapCli(['--config', 'unused-input-on-unsupported-host.json']), { code: 'MAP_CONFIG_INVALID' });
  const result = spawnSync(process.execPath, [cli, '--config', 'unused-input-on-unsupported-host.json'], {
    encoding: 'utf8', timeout: 3000, killSignal: 'SIGKILL',
  });
  assert.equal(result.error, undefined); assert.equal(result.status, 1);
  assert.equal(result.stdout, ''); assert.equal(result.stderr, 'MAP_START_FAILED\n');
  return true;
}
async function validConfig(t, { linked = false, padded = false } = {}) {
  if (await unsupportedHost()) return;
  const dir = await mkdtemp(join(tmpdir(), 'agent-map-cli-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const token = createMapToken(), password = 'private-test-password';
  const config = join(dir, 'host.json');
  let contents = JSON.stringify({ neo4j: { uri: 'bolt://127.0.0.1:1', username: 'reader', passwordEnv: 'MAP_TEST_PASSWORD' },
    credentials: [{ tokenEnv: 'MAP_TEST_TOKEN', scope: { subject: 'cli', companyId: 'company', tenantIds: ['tenant'], teamIds: ['team'], allTeams: false } }], port: 0 });
  if (padded) contents = contents.padEnd(128 * 1024, ' ');
  await writeFile(config, contents);
  const input = linked ? join(dir, 'config-link.json') : config;
  if (linked) await symlink(config, input);
  const child = spawn(process.execPath, [cli, '--config', input], {
    env: { ...process.env, MAP_TEST_PASSWORD: password, MAP_TEST_TOKEN: token }, stdio: ['ignore', 'pipe', 'pipe'],
  });
  t.after(() => child.kill('SIGKILL'));
  let out = '', error = ''; child.stdout.on('data', data => { out += data; }); child.stderr.on('data', data => { error += data; });
  const exited = new Promise(resolve => child.once('exit', (code, signal) => resolve({ code, signal })));
  const line = await new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('CLI did not start')), 5000);
    child.once('error', reject); child.once('exit', () => { clearTimeout(timer); reject(new Error('CLI exited before startup')); });
    child.stdout.on('data', () => { if (out.includes('\n')) { clearTimeout(timer); resolve(out.trim()); } });
  });
  const announced = JSON.parse(line); assert.equal(announced.mode, 'read-only');
  assert.match(announced.url, /^http:\/\/127\.0\.0\.1:\d+$/);
  const response = await fetch(announced.url + '/v1/query', { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{"operation":"list_agents","args":{}}' });
  assert.equal(response.status, 401);
  child.kill('SIGTERM'); assert.deepEqual(await exited, { code: 0, signal: null });
  assert.equal(error, ''); assert.ok(!out.includes(token)); assert.ok(!out.includes(password));
}
test(onSupportedHost('CLI reads host scope and secrets from named environment variables, logs no credentials and shuts down'), validConfig);
test(onSupportedHost('CLI retains symlinks to regular configuration files'), async t => validConfig(t, { linked: true }));
test(onSupportedHost('CLI accepts a complete configuration at the exact byte limit'), async t => validConfig(t, { padded: true }));
test('CLI startup failures produce only a stable safe error', async () => {
  const child = spawn(process.execPath, [cli, '--unexpected', 'private-value'], { stdio: ['ignore', 'pipe', 'pipe'] });
  let out = '', error = ''; child.stdout.on('data', data => { out += data; }); child.stderr.on('data', data => { error += data; });
  const code = await new Promise(resolve => child.once('exit', resolve));
  assert.equal(code, 1); assert.equal(out, ''); assert.equal(error, 'MAP_START_FAILED\n');
});

test(onSupportedHost('CLI rejects FIFO configuration without waiting for a writer'), async t => {
  if (await unsupportedHost()) return;
  const dir = await mkdtemp(join(tmpdir(), 'agent-map-cli-fifo-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const fifo = join(dir, 'config.fifo');
  assert.equal(spawnSync('mkfifo', [fifo], { encoding: 'utf8' }).status, 0);
  const result = spawnSync(process.execPath, [cli, '--config', fifo], {
    encoding: 'utf8', timeout: 3000, killSignal: 'SIGKILL',
  });
  assert.equal(result.error, undefined); assert.equal(result.status, 1);
  assert.equal(result.stdout, ''); assert.equal(result.stderr, 'MAP_START_FAILED\n');
});

test('CLI rejects nonregular and oversized inputs with stable diagnostics', async t => {
  const dir = await mkdtemp(join(tmpdir(), 'agent-map-cli-input-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const oversized = join(dir, 'oversized.json');
  await writeFile(oversized, 'credential-canary'.padEnd(128 * 1024 + 1, ' '));
  for (const input of [dir, oversized]) {
    const result = spawnSync(process.execPath, [cli, '--config', input], {
      encoding: 'utf8', timeout: 3000, killSignal: 'SIGKILL',
    });
    assert.equal(result.error, undefined); assert.equal(result.status, 1);
    assert.equal(result.stdout, ''); assert.equal(result.stderr, 'MAP_START_FAILED\n');
  }
});

test(onSupportedHost('CLI bounds growing configuration reads and closes the checked descriptor'), async t => {
  if (await unsupportedHost()) return;
  const dir = await mkdtemp(join(tmpdir(), 'agent-map-cli-growth-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const config = join(dir, 'growing.json'); await writeFile(config, '{}');
  // Grow a real file after metadata is returned, without timing a concurrent writer.
  const script = `
    import fs from 'node:fs/promises';
    import { syncBuiltinESMExports } from 'node:module';
    import { pathToFileURL } from 'node:url';
    const [filename, entry] = process.argv.slice(1);
    const original = { open: fs.open, stat: fs.stat, readFile: fs.readFile };
    let bytes = 0, closed = false;
    const grow = () => fs.appendFile(filename, 'credential-canary'.padEnd(256 * 1024, ' '));
    fs.stat = async (...args) => { const info = await original.stat(...args); if (args[0] === filename) await grow(); return info; };
    fs.readFile = async (...args) => { const data = await original.readFile(...args); if (args[0] === filename) bytes += data.length; return data; };
    fs.open = async (...args) => {
      const file = await original.open(...args); if (args[0] !== filename) return file;
      const stat = file.stat.bind(file), read = file.read.bind(file), close = file.close.bind(file);
      file.stat = async (...values) => { const info = await stat(...values); await grow(); return info; };
      file.read = async (...values) => { const result = await read(...values); bytes += result.bytesRead; return result; };
      file.close = async () => { await close(); closed = true; };
      return file;
    };
    syncBuiltinESMExports();
    const { runMapCli } = await import(pathToFileURL(entry));
    let code;
    try { await runMapCli(['--config', filename]); } catch (error) { code = error.code; }
    process.stdout.write(JSON.stringify({ code, bytes, closed }));
  `;
  const result = spawnSync(process.execPath, ['--input-type=module', '-e', script, config, cli], {
    encoding: 'utf8', timeout: 3000, killSignal: 'SIGKILL',
  });
  assert.equal(result.error, undefined); assert.equal(result.status, 0); assert.equal(result.stderr, '');
  assert.deepEqual(JSON.parse(result.stdout), { code: 'MAP_CONFIG_INVALID', bytes: 128 * 1024 + 1, closed: true });
});
