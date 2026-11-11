import assert from 'node:assert/strict';
import test from 'node:test';
import { cpSync, mkdtempSync, realpathSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { GuardError, isGuardError } from '@shieldaai/agent-guard';
import { runConformance } from '../dist/index.js';

test('scenarios pass against a guard from a second installed copy of core', { timeout: 30_000 }, async t => {
  // A host may resolve a different copy of core than this package does (two versions in node_modules).
  const directory = realpathSync(mkdtempSync(join(tmpdir(), 'agent-guard-second-copy-')));
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  const core = new URL('../../core/', import.meta.url);
  cpSync(new URL('dist', core), join(directory, 'dist'), { recursive: true });
  cpSync(new URL('package.json', core), join(directory, 'package.json'));
  const second = await import(pathToFileURL(join(directory, 'dist/index.js')).href);
  assert.notEqual(second.GuardError, GuardError, 'the copy is a distinct module instance');
  const foreign = new second.GuardError('GRANT_DENIED');
  assert.equal(foreign instanceof GuardError, false, 'instanceof fails across copies');
  assert.equal(isGuardError(foreign), true, 'the brand check does not');
  assert.equal(isGuardError(Object.assign(new Error('x'), { code: 'GRANT_DENIED' })), false);
  const report = await runConformance({ createGuard: options => new second.AgentGuard(options) });
  assert.equal(
    report.passed,
    true,
    JSON.stringify(
      report.results.filter(({ passed }) => !passed),
      null,
      2,
    ),
  );
});
