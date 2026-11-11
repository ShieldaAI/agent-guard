#!/usr/bin/env node
// Host verifier: built-ins, OpenSSL and Docker only. All credentials and state are disposable.
import assert from 'node:assert/strict';
import { parseArgs } from 'node:util';
import { execFileSync, spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, writeFileSync, mkdirSync, rmSync, realpathSync } from 'node:fs';
import { randomUUID } from 'node:crypto';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
const { values } = parseArgs({ options: { image: { type: 'string' }, output: { type: 'string' } }, strict: true });
assert.match(values.image ?? '', /^(?:sha256:[a-f0-9]{64}|[^\s]+@sha256:[a-f0-9]{64})$/);
const cwd = fileURLToPath(new URL('../../', import.meta.url)), directory = realpathSync(mkdtempSync(join(tmpdir(), 'agent-ops-linux-')));
const docker = (...args) => execFileSync('docker', args, { encoding: 'utf8', maxBuffer: 4 * 1024 * 1024, timeout: 120_000 });
const containers = [], volumes = [];
const result = { schema: 1, measuredAt: new Date().toISOString(), status: 'failed' };
try {
  const openssl = (...args) => execFileSync('openssl', args, { cwd: directory, stdio: 'ignore', timeout: 30_000 });
  openssl('req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes', '-keyout', 'ca.key', '-out', 'ca.pem', '-days', '2', '-subj', '/CN=Disposable Operations Test CA');
  openssl('req', '-new', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes', '-keyout', 'leaf.key', '-out', 'leaf.csr', '-subj', '/CN=localhost');
  writeFileSync(join(directory, 'extensions'), 'subjectAltName=DNS:localhost,IP:127.0.0.1\nbasicConstraints=CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n', { mode: 0o600 });
  openssl('x509', '-req', '-in', 'leaf.csr', '-CA', 'ca.pem', '-CAkey', 'ca.key', '-CAcreateserial', '-out', 'leaf.pem', '-days', '2', '-extfile', 'extensions');
  const tls = { ca: readFileSync(join(directory, 'ca.pem'), 'utf8'), cert: readFileSync(join(directory, 'leaf.pem'), 'utf8'), key: readFileSync(join(directory, 'leaf.key'), 'utf8') };
  const image = JSON.parse(docker('image', 'inspect', values.image))[0];
  result.verificationImage = image.Id; result.imagePlatform = `${image.Os}/${image.Architecture}`;
  assert.equal(image.Os, 'linux'); assert.equal(image.Config.User, '10001:10001');
  const engine = JSON.parse(docker('version', '--format', '{{json .Server}}'));
  result.docker = { version: engine.Version, os: engine.Os, arch: engine.Arch };
  assert.equal(engine.Os, 'linux');
  const compose = JSON.parse(execFileSync('docker', ['compose', '-f', 'deployment/production/compose.yaml', '--profile', 'maintenance', '--profile', 'onboarding', '--profile', 'custody', 'config', '--format', 'json'], {
    cwd, encoding: 'utf8', env: { ...process.env, AGENT_OPS_IMAGE: image.Id, AGENT_OPS_DATA: join(directory, 'data'),
      AGENT_OPS_WITNESS: join(directory, 'witness'), AGENT_OPS_CONFIG: join(directory, 'config'),
      AGENT_OPS_HISTORY: join(directory, 'history'),
      AGENT_OPS_CUSTODY_DATA: join(directory, 'custody-data'), AGENT_OPS_CUSTODY_WITNESS: join(directory, 'custody-witness'),
      AGENT_OPS_CUSTODY_KEYS: join(directory, 'custody-keys'), AGENT_OPS_BACKUPS: join(directory, 'backups'),
      AGENT_OPS_ONBOARDING: join(directory, 'input'), AGENT_OPS_CONFIG_FILE: '/run/agent-ops/company/config.json' }, timeout: 15_000 }));
  for (const name of ['agent-ops', 'maintenance', 'onboarding', 'custody']) {
    const service = compose.services[name]; assert.equal(service.read_only, true); assert.equal(service.user, '10001:10001');
    assert.deepEqual(service.cap_drop, ['ALL']); assert.ok(service.security_opt.includes('no-new-privileges:true'));
    assert.equal(service.pull_policy, 'never'); assert.equal(service.pids_limit, 128);
    assert.equal(service.volumes.length, name === 'onboarding' ? 5 : name === 'custody' ? 8 : 4); assert.ok(service.volumes.every(volume => volume.type === 'bind' && volume.bind.create_host_path === false));
    assert.equal(service.volumes.find(volume => volume.target === '/run/agent-ops').read_only ?? false, name === 'agent-ops');
    assert.equal(service.volumes.find(volume => volume.target === '/var/lib/agent-ops-history').read_only ?? false, name === 'agent-ops');
    assert.equal(service.volumes.some(volume => volume.target.includes('docker.sock')), false);
  }
  assert.equal(compose.services['agent-ops'].ports[0].host_ip, '127.0.0.1');
  assert.equal(compose.services.maintenance.network_mode, 'none');
  assert.equal(compose.services.custody.network_mode, 'none');
  const offlineTargets = ['/var/lib/agent-ops-custody', '/var/lib/agent-ops-custody-witness', '/run/agent-ops-custody-keys', '/var/lib/agent-ops-backups'];
  for (const target of offlineTargets) {
    assert.ok(compose.services.custody.volumes.some(volume => volume.target === target));
    for (const service of ['agent-ops', 'maintenance', 'onboarding']) assert.equal(compose.services[service].volumes.some(volume => volume.target === target), false);
  }
  assert.equal(compose.services.onboarding.ports?.length ?? 0, 0);
  assert.equal(compose.services.onboarding.volumes.find(volume => volume.target === '/run/company').read_only, true);
  assert.notEqual(compose.services.onboarding.network_mode, 'host'); assert.notEqual(compose.services.onboarding.network_mode, 'none');
  assert.deepEqual(compose.services['agent-ops'].command, ['--config', '/run/agent-ops/company/config.json']);
  assert.ok(compose.services['agent-ops'].healthcheck.test.includes('/run/agent-ops/company/config.json')); result.composeControls = 'passed';
  function verify(script, input = '', persistence = false) {
    const name = `agent-ops-check-${randomUUID()}`; containers.push(name);
    const mounts = [];
    if (persistence) {
      for (const area of ['data', 'witness', 'config', 'history']) {
        const volume = `agent-ops-check-${area}-${randomUUID()}`;
        docker('volume', 'create', volume); volumes.push(volume);
        mounts.push('--mount', `type=volume,source=${volume},target=/fixtures/${area}`);
      }
      // Only these newly created disposable volumes are prepared as root.
      docker('run', '--rm', '--network', 'none', '--read-only', '--cap-drop', 'ALL', '--cap-add', 'CHOWN', '--user', '0:0',
        ...mounts, '--entrypoint', 'node', image.Id, '-e',
        'const fs=require("node:fs"); for(const n of ["data","witness","config","history"]){const p="/fixtures/"+n;fs.chmodSync(p,0o700);fs.chownSync(p,10001,10001)}');
    }
    docker('create', '-i', '--name', name, '--network', 'none', '--read-only', '--user', '10001:10001', '--cap-drop', 'ALL',
      '--security-opt', 'no-new-privileges', '--pids-limit', '128', '--memory', '512m', '--cpus', '1',
      '--tmpfs', '/tmp:rw,noexec,nosuid,nodev,size=32m,mode=0700,uid=10001,gid=10001',
      ...(persistence ? ['--tmpfs', '/fixtures:rw,noexec,nosuid,nodev,size=8m,mode=0700,uid=10001,gid=10001', ...mounts, '-e', 'AGENT_OPS_VERIFY_PERSISTENCE=1'] : []),
      '--entrypoint', 'node', image.Id, script);
    const actual = JSON.parse(docker('inspect', name))[0].HostConfig;
    assert.equal(actual.ReadonlyRootfs, true); assert.equal(actual.NetworkMode, 'none'); assert.equal(actual.Memory, 512 * 1024 * 1024);
    assert.equal(actual.PidsLimit, 128); assert.equal(actual.NanoCpus, 1e9); assert.deepEqual(actual.CapDrop, ['ALL']);
    assert.ok(actual.SecurityOpt.includes('no-new-privileges')); assert.equal(actual.Privileged, false);
    const run = spawnSync('docker', ['start', '-ai', name], { input, encoding: 'utf8', maxBuffer: 4 * 1024 * 1024, timeout: 120_000 });
    assert.equal(run.status, 0, run.stderr || run.error?.message); const report = JSON.parse(run.stdout.trim());
    assert.equal(report.status, 'passed');
    if (persistence) {
      const runtimeMounts = mounts.map(value => /target=\/fixtures\/(?:config|history)$/.test(value) ? `${value},readonly` : value);
      const check = JSON.parse(docker('run', '--rm', '--network', 'none', '--read-only', '--user', '10001:10001', '--cap-drop', 'ALL',
        '--security-opt', 'no-new-privileges', '--pids-limit', '128', '--memory', '512m', '--cpus', '1',
        '--tmpfs', '/tmp:rw,noexec,nosuid,nodev,size=32m,mode=0700,uid=10001,gid=10001', ...runtimeMounts,
        image.Id, 'check', '--config', '/fixtures/config/company/config.json'));
      assert.equal(check.status, 'verified');
      report.reopenedInFreshContainer = true;
      report.runtimeConfigAndHistoryReadOnly = true;
      result.storage = { driver: JSON.parse(docker('volume', 'inspect', volumes[0]))[0].Driver,
        separateDataWitnessConfigAndHistoryVolumes: true, freshContainerReopen: true };
    }
    return report;
  }
  result.maintenance = verify('deployment/production/verify-maintenance.mjs');
  result.cli = verify('deployment/production/verify-cli.mjs', JSON.stringify(tls), true);
  result.status = 'passed';
  result.limits = ['Disposable local Linux containers; no customer deployment', 'CLI SIGKILL and cold file recovery; no guest kernel crash or physical host power loss',
    'Compose configuration, hardened container controls and persistent Linux named volumes verified; production bind-volume provisioning remains operator-owned'];
} catch (error) {
  result.error = error.code ?? error.name; process.stderr.write(`${error.message}\n`); process.exitCode = 1;
} finally {
  for (const name of containers) { try { docker('rm', '-f', '-v', name); } catch { result.status = 'failed'; result.cleanupFailed = true; process.exitCode = 1; } }
  for (const name of volumes) { try { docker('volume', 'rm', name); } catch { result.status = 'failed'; result.cleanupFailed = true; process.exitCode = 1; } }
  rmSync(directory, { recursive: true, force: true });
  if (values.output) { mkdirSync(dirname(values.output), { recursive: true }); writeFileSync(values.output, JSON.stringify(result, null, 2) + '\n', { flag: 'wx', mode: 0o600 }); }
  process.stdout.write(JSON.stringify(result) + '\n');
}
