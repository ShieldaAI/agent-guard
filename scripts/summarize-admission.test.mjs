import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { summarizeAdmission, summarizeAdmissionFile } from './summarize-admission.mjs';

const report = {
  gate: {
    passed: false, maximumRatio: 1.1, baselineP95Ms: 35.801598, pollingP95Ms: 51.407993, regressionPercent: 43.591336,
    failureReasons: [{ phase: 2, code: 'POLL_CADENCE_SKIPPED' }, { code: 'ADMISSION_REGRESSION_EXCEEDED' }],
  },
  phases: [{ polling: null }, { polling: { skippedBusy: 1 } }, { polling: { skippedBusy: 3 } }, { polling: null }],
};

test('summarizes the gate result, measures and reasons', () => {
  const summary = summarizeAdmission(report, 'Nightly admission');
  assert.match(summary, /^### Nightly admission/);
  assert.match(summary, /Result: \*\*failed\*\*/);
  assert.match(summary, /\| Baseline p95 \| 35\.80 ms \|/);
  assert.match(summary, /\| Overhead \| 43\.59% \(limit 10%\) \|/);
  assert.match(summary, /\| Skipped polls \| 4 \|/);
  assert.match(summary, /POLL_CADENCE_SKIPPED \(phase 2\), ADMISSION_REGRESSION_EXCEEDED/);
});

test('reports a passing gate without reasons', () => {
  const summary = summarizeAdmission({ gate: { passed: true, maximumRatio: 1.1, regressionPercent: -0.27, failureReasons: [] }, phases: [] }, 'x');
  assert.match(summary, /Result: \*\*passed\*\*/);
  assert.match(summary, /\| Failure reasons \| none \|/);
});

test('states a missing, malformed or gateless report instead of failing', t => {
  const dir = mkdtempSync(join(tmpdir(), 'summarize-admission-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  assert.match(summarizeAdmissionFile(join(dir, 'absent.json'), 'x'), /No readable admission report/);
  writeFileSync(join(dir, 'bad.json'), '{');
  assert.match(summarizeAdmissionFile(join(dir, 'bad.json'), 'x'), /No readable admission report/);
  writeFileSync(join(dir, 'empty.json'), '{}');
  assert.match(summarizeAdmissionFile(join(dir, 'empty.json'), 'x'), /No admission gate result/);
});

test('keeps Markdown and HTML out of untrusted titles and codes', () => {
  const summary = summarizeAdmission({ gate: { passed: false, failureReasons: [{ code: '<img src=x>|`' }] }, phases: [] }, '<b>|title');
  assert.doesNotMatch(summary, /[<>`]/);
  assert.match(summary, /^### btitle/);
});
