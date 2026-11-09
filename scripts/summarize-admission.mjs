// Prints a short Markdown summary of an admission-during-polling report for a CI job
// summary. It reads only the gate fields and never fails the job: the report itself
// stays the evidence, and a missing or malformed report is stated as such.
import { readFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';

const MAX_REPORT_BYTES = 32 * 1024 * 1024;

const number = (value, digits) => (typeof value === 'number' && Number.isFinite(value) ? value.toFixed(digits) : 'n/a');
const text = value => String(value).replace(/[^A-Za-z0-9 _().,:%/+-]/g, '').slice(0, 120);

export function summarizeAdmission(report, title) {
  const heading = `### ${text(title)}`;
  const gate = report && typeof report === 'object' ? report.gate : undefined;
  if (!gate || typeof gate !== 'object') return `${heading}\n\nNo admission gate result was recorded.\n`;
  const reasons = Array.isArray(gate.failureReasons)
    ? gate.failureReasons.map(reason => text(`${reason?.code ?? 'UNKNOWN'}${reason?.phase === undefined ? '' : ` (phase ${reason.phase})`}`))
    : [];
  const skipped = Array.isArray(report.phases)
    ? report.phases.reduce((total, phase) => total + (Number.isInteger(phase?.polling?.skippedBusy) ? phase.polling.skippedBusy : 0), 0)
    : 'n/a';
  return [
    heading,
    '',
    `Timing signal only; not a required check. Result: **${gate.passed === true ? 'passed' : 'failed'}**.`,
    '',
    '| Measure | Value |',
    '| --- | --- |',
    `| Baseline p95 | ${number(gate.baselineP95Ms, 2)} ms |`,
    `| Polling p95 | ${number(gate.pollingP95Ms, 2)} ms |`,
    `| Overhead | ${number(gate.regressionPercent, 2)}% (limit ${number(((gate.maximumRatio ?? NaN) - 1) * 100, 0)}%) |`,
    `| Skipped polls | ${skipped} |`,
    `| Failure reasons | ${reasons.length ? reasons.join(', ') : 'none'} |`,
    '',
  ].join('\n');
}

export function summarizeAdmissionFile(path, title) {
  let report;
  try {
    const raw = readFileSync(path);
    if (raw.byteLength > MAX_REPORT_BYTES) throw new Error('REPORT_TOO_LARGE');
    report = JSON.parse(raw.toString('utf8'));
  } catch {
    return `### ${text(title)}\n\nNo readable admission report was produced.\n`;
  }
  return summarizeAdmission(report, title);
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? '').href) {
  const [path, title = 'Admission during inventory polling'] = process.argv.slice(2);
  process.stdout.write(summarizeAdmissionFile(path ?? '', title));
}
