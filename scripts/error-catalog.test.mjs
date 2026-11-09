import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { GuardErrorCatalog, GuardErrorCode } from '@shieldaai/agent-guard';
import { renderErrorCatalog, catalogPath } from './error-catalog.mjs';
import { executorResponseStatus, executorResponseRetryable, isExecutorResponseCode } from '../packages/executor/dist/response-code.js';

test('the catalog covers exactly every GuardErrorCode', () => {
  assert.deepEqual(Object.keys(GuardErrorCatalog).sort(), Object.values(GuardErrorCode).sort());
  for (const info of Object.values(GuardErrorCatalog)) {
    assert.equal(typeof info.retryable, 'boolean');
    assert.ok(info.meaning.length > 10 && info.cause.length > 10);
  }
  assert.equal(Object.isFrozen(GuardErrorCatalog), true);
});

test('docs/errors.md matches the generated catalog', () => {
  assert.equal(readFileSync(catalogPath, 'utf8'), renderErrorCatalog(), 'run: node scripts/error-catalog.mjs --write');
});

test('no code that may follow a dispatched effect is marked retryable', () => {
  for (const code of ['TOOL_FAILED', 'EXECUTION_ABORTED', 'RESULT_INVALID', 'COST_REPORT_INVALID', 'OPERATION_FAILED', 'ACTION_USED']) {
    assert.equal(executorResponseRetryable(code), false, code);
  }
});

test('every executor response code has a deliberate status', () => {
  const expected = { UNAUTHENTICATED: 401, GRANT_DENIED: 403, INVALID_PREPARED: 404, ACTION_USED: 409, CONCURRENCY_EXCEEDED: 429, TOOL_FAILED: 503, REQUEST_INVALID: 400 };
  for (const [code, status] of Object.entries(expected)) {
    assert.ok(isExecutorResponseCode(code), code);
    assert.equal(executorResponseStatus(code), status, code);
  }
});
