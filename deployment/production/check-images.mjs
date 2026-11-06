#!/usr/bin/env node
// Compare actual application bytes; a successful test-only image is insufficient.
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname } from 'node:path';
import { parseArgs } from 'node:util';

const { values } = parseArgs({ strict: true, options: {
  production: { type: 'string' }, verification: { type: 'string' }, output: { type: 'string' },
} });
const identity = /^(?:sha256:[a-f0-9]{64}|[^\s]+@sha256:[a-f0-9]{64})$/;
assert.match(values.production ?? '', identity); assert.match(values.verification ?? '', identity);
const script = `const fs=require('node:fs'),crypto=require('node:crypto');const files={};
for(const p of ['/usr/local/lib/node_modules','/usr/local/bin/npm','/usr/local/bin/npx','/usr/local/bin/corepack','/usr/local/bin/yarn','/usr/local/bin/yarnpkg','/usr/local/bin/pnpm','/usr/local/bin/pnpx'])if(fs.existsSync(p))throw Error('Global package manager remains: '+p);
if(fs.readdirSync('/opt').some(n=>n.startsWith('yarn')))throw Error('Global Yarn remains');
function visit(path){for(const entry of fs.readdirSync(path,{withFileTypes:true})){const p=path+'/'+entry.name;
if(entry.isDirectory())visit(p);else if(entry.isSymbolicLink())files[p]={link:fs.readlinkSync(p)};
else if(entry.isFile())files[p]={sha256:crypto.createHash('sha256').update(fs.readFileSync(p)).digest('hex')};
else throw Error('Unexpected image entry: '+p)}}visit('/app');process.stdout.write(JSON.stringify({node:process.versions.node,files}));`;
function inspect(image) {
  return JSON.parse(execFileSync('docker', ['run', '--rm', '--network', 'none', '--read-only', '--user', '10001:10001',
    '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges', '--pids-limit', '128', '--memory', '512m',
    '--entrypoint', 'node', image, '-e', script], { encoding: 'utf8', timeout: 60_000, maxBuffer: 8 * 1024 * 1024 }));
}
const production = inspect(values.production), verification = inspect(values.verification);
assert.equal(production.node, verification.node);
const onlyVerification = ['/app/deployment/production/verify-cli.mjs', '/app/packages/agent-map/test/helpers/oidc-provider.mjs'];
for (const path of onlyVerification) {
  assert.equal(production.files[path], undefined, `Test fixture in production: ${path}`);
  assert.ok(verification.files[path], `Missing verification fixture: ${path}`); delete verification.files[path];
}
assert.deepEqual(production.files, verification.files, 'Production and tested application bytes differ');
const manifest = Object.fromEntries(Object.entries(production.files).sort(([a], [b]) => a.localeCompare(b, 'en')));
const result = { status: 'passed', measuredAt: new Date().toISOString(), productionImage: values.production,
  verificationImage: values.verification, node: production.node, identicalApplicationEntries: Object.keys(manifest).length,
  globalPackageManagersAbsent: true,
  applicationManifestSha256: createHash('sha256').update(JSON.stringify(manifest)).digest('hex'),
  excludedVerificationFixtures: onlyVerification, applicationManifest: manifest };
if (values.output) {
  mkdirSync(dirname(values.output), { recursive: true });
  writeFileSync(values.output, JSON.stringify(result, null, 2) + '\n', { flag: 'wx', mode: 0o600 });
}
const { applicationManifest: _manifest, ...summary } = result;
process.stdout.write(JSON.stringify(summary) + '\n');
