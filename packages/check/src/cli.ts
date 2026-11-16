#!/usr/bin/env node
import { readFileSync, realpathSync, writeFileSync } from 'node:fs';

/** Reports and baselines can name internal paths and masked secrets: write them for the owner only. */
const PRIVATE_FILE = { mode: 0o600 } as const;
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseArgs } from 'node:util';
import { formatBaseline, parseBaseline, shouldFail, DEFAULT_CONFIG, parseConfig, type FailOn } from './config.js';
import { diffScans, scan, type ScanDiff } from './scan.js';
import { formatJson, formatMarkdown, formatSarif, formatText, TOOL_NAME, TOOL_VERSION } from './report.js';
import { SEVERITY_ORDER, type Confidence, type ScanResult } from './types.js';

const USAGE = `Usage: ${TOOL_NAME} [path] [options]

Shows what each AI agent in a repository can do and flags authority it does not need.
Reads files only: it never runs repository code and makes no network calls.

Options:
  --format <text|json|sarif|markdown>  Output format (default: text)
  --output <file>                      Write the report to a file instead of stdout
  --fail-on <severity|none>            Exit 1 at or above this severity (default: high, or fail_on in .agc.yaml)
  --min-confidence <high|low>          Let low-confidence findings fail the run (default: high)
  --base <git-ref>                     Compare with this commit; report only what the change made worse
  --baseline <file>                    Ignore findings listed in this baseline file
  --write-baseline <file>              Write current findings to a baseline file and exit 0
  --version                            Print the version
  --help                               Print this help

Exit codes: 0 no findings at or above --fail-on, 1 findings, 2 usage or read error.
`;

export interface CliIo {
  readonly stdout: (text: string) => void;
  readonly stderr: (text: string) => void;
  readonly cwd: string;
}

/** Runs the CLI and returns the exit code. Exposed for tests. */
export function runCli(argv: readonly string[], io: CliIo): number {
  let parsed;
  try {
    parsed = parseArgs({
      args: [...argv],
      allowPositionals: true,
      options: {
        format: { type: 'string', default: 'text' },
        output: { type: 'string' },
        'fail-on': { type: 'string' },
        'min-confidence': { type: 'string' },
        base: { type: 'string' },
        baseline: { type: 'string' },
        'write-baseline': { type: 'string' },
        version: { type: 'boolean', default: false },
        help: { type: 'boolean', default: false },
      },
    });
  } catch (error) {
    io.stderr(`${error instanceof Error ? error.message : String(error)}\n\n${USAGE}`);
    return 2;
  }
  const { values, positionals } = parsed;
  if (values.help) {
    io.stdout(USAGE);
    return 0;
  }
  if (values.version) {
    io.stdout(`${TOOL_VERSION}\n`);
    return 0;
  }
  if (positionals.length > 1) {
    io.stderr(`Expected at most one path.\n\n${USAGE}`);
    return 2;
  }
  const format = values.format;
  if (!['text', 'json', 'sarif', 'markdown'].includes(format)) {
    io.stderr(`Unknown format "${format}".\n`);
    return 2;
  }
  const failOnFlag = values['fail-on'];
  if (failOnFlag !== undefined && failOnFlag !== 'none' && !SEVERITY_ORDER.includes(failOnFlag as never)) {
    io.stderr(`--fail-on must be one of ${[...SEVERITY_ORDER].reverse().join(', ')}, none.\n`);
    return 2;
  }
  const minFlag = values['min-confidence'];
  if (minFlag !== undefined && minFlag !== 'high' && minFlag !== 'low') {
    io.stderr('--min-confidence must be high or low.\n');
    return 2;
  }
  const root = resolve(io.cwd, positionals[0] ?? '.');
  try {
    let config = DEFAULT_CONFIG;
    try {
      config = parseConfig(readFileSync(resolve(root, '.agc.yaml'), 'utf8'));
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
    }
    const baseline = values.baseline
      ? parseBaseline(readFileSync(resolve(io.cwd, values.baseline), 'utf8'))
      : new Set<string>();
    const head = scan({ root, config, baseline });
    if (values['write-baseline']) {
      writeFileSync(
        resolve(io.cwd, values['write-baseline']),
        formatBaseline([...head.findings, ...head.suppressed.map(s => s.finding)]),
        PRIVATE_FILE,
      );
      io.stdout(
        `Wrote ${head.findings.length + head.suppressed.length} fingerprint(s) to ${values['write-baseline']}.\n`,
      );
      return 0;
    }
    let diff: ScanDiff | undefined;
    if (values.base) diff = diffScans(scan({ root, ref: values.base, config, baseline }), head);
    const report = render(format, head, diff);
    if (values.output) writeFileSync(resolve(io.cwd, values.output), report, PRIVATE_FILE);
    else io.stdout(report);
    for (const error of head.errors) io.stderr(`warning: could not read ${error.file}: ${error.message}\n`);
    const failOn = (failOnFlag ?? config.failOn) as FailOn;
    const minConfidence = (minFlag ?? config.minConfidence) as Confidence;
    return shouldFail(diff ? diff.added : head.findings, failOn, minConfidence) ? 1 : 0;
  } catch (error) {
    io.stderr(`${TOOL_NAME}: ${error instanceof Error ? error.message : String(error)}\n`);
    return 2;
  }
}

function render(format: string, result: ScanResult, diff: ScanDiff | undefined): string {
  if (format === 'json') return formatJson(result, diff);
  if (format === 'sarif') return formatSarif(result, diff ? diff.added : result.findings);
  if (format === 'markdown') return formatMarkdown(result, diff);
  return formatText(result, diff);
}

function isEntry(): boolean {
  if (!process.argv[1]) return false;
  try {
    return realpathSync(process.argv[1]) === realpathSync(fileURLToPath(import.meta.url));
  } catch {
    return false;
  }
}

if (isEntry()) {
  process.exitCode = runCli(process.argv.slice(2), {
    stdout: text => process.stdout.write(text),
    stderr: text => process.stderr.write(text),
    cwd: process.cwd(),
  });
}
