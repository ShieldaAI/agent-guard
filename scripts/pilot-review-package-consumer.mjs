// Exercise the npm launcher and verifier after installation with detached test-only signatures.
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { verifyPilotReview } from '@shieldaai/agent-guard-executor/pilot';
import { createPilotReviewFixture } from './pilot-review-fixture.mjs';

const { policy, candidateBytes, bundle } = createPilotReviewFixture();
assert.throws(() => verifyPilotReview(policy, candidateBytes, bundle), { message: 'Pilot review verification failed' });
const expected = verifyPilotReview(policy, candidateBytes, bundle, 'rehearsal');
assert.equal(expected.mode, 'rehearsal');
assert.equal(expected.status, 'verified');
writeFileSync('policy.json', JSON.stringify(policy), { mode: 0o600 });
writeFileSync('candidate.bin', candidateBytes, { mode: 0o600 });
writeFileSync('evidence.json', JSON.stringify(bundle), { mode: 0o600 });
const args = ['--policy', 'policy.json', '--candidate', 'candidate.bin', '--bundle', 'evidence.json'];
function launch(extra = []) {
  const executable = join('node_modules', '.bin', 'agent-guard-pilot-review');
  return process.platform === 'win32'
    ? spawnSync('cmd.exe', ['/d', '/c', executable + '.cmd', ...args, ...extra], { encoding: 'utf8' })
    : spawnSync(executable, [...args, ...extra], { encoding: 'utf8' });
}
const rehearsal = launch(['--rehearsal']);
assert.equal(rehearsal.status, 0, rehearsal.stderr);
assert.deepEqual(JSON.parse(rehearsal.stdout), JSON.parse(JSON.stringify(expected)));
const company = launch();
assert.equal(company.status, 1);
assert.equal(company.stdout, '');
writeFileSync('candidate.bin', Buffer.from('a different release'));
const changed = launch(['--rehearsal']);
assert.equal(changed.status, 1);
assert.equal(changed.stdout, '');

// Exercise the default entry point with separate, disposable enrollment. This directory is removed by the pack check.
const scoped = createPilotReviewFixture({
  policy(enrolled) {
    enrolled.mode = 'company-pilot';
  },
});
writeFileSync('policy.json', JSON.stringify(scoped.policy));
writeFileSync('candidate.bin', scoped.candidateBytes);
writeFileSync('evidence.json', JSON.stringify(scoped.bundle));
const accepted = launch();
assert.equal(accepted.status, 0, accepted.stderr);
assert.equal(JSON.parse(accepted.stdout).mode, 'company-pilot');
const incorrectMode = launch(['--rehearsal']);
assert.equal(incorrectMode.status, 1);
assert.equal(incorrectMode.stdout, '');
console.log(
  'Installed pilot reviewer checked both modes with disposable keys and rejected scope mismatches and altered bytes.',
);
