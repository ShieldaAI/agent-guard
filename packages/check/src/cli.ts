#!/usr/bin/env node
import {
  closeSync,
  constants,
  fchmodSync,
  fstatSync,
  lstatSync,
  openSync,
  readFileSync,
  realpathSync,
  writeFileSync,
} from 'node:fs';
import { homedir } from 'node:os';
import { relative, resolve, sep } from 'node:path';
import { readUserConfig } from './user.js';
import { fileURLToPath } from 'node:url';
import { parseArgs } from 'node:util';
import {
  formatBaseline,
  parseBaseline,
  shouldFail,
  DEFAULT_CONFIG,
  parseConfig,
  type CheckConfig,
  type FailOn,
} from './config.js';
import { diffScans, scan, type ScanDiff, type ScanOptions } from './scan.js';
import {
  formatInventory,
  formatJson,
  formatMarkdown,
  formatSarif,
  formatText,
  RULES_URI,
  TOOL_NAME,
  TOOL_VERSION,
} from './report.js';
import { SEVERITY_ORDER, type Confidence, type Finding, type ScanResult } from './types.js';
import { DirectorySource, GitSource, safeRelative, type FileSource } from './source.js';
import { fetchLiveEvidence, AgentMapError, type LiveEvidence } from './agent-map.js';
import { fetchBranchRules, GitHubError, isRepoName, type BranchRules } from './github.js';
import { importSarif } from './sarif-import.js';
import { formatDiff, planFixes } from './fix.js';
import { RULES } from './rules/index.js';
import type { TextFile } from './model.js';
import { oneLine } from './text.js';

const MAX_INPUT_BYTES = 16 * 1024 * 1024;

/**
 * Reports and baselines can name internal paths and masked secrets: write them for the owner only,
 * also when the file already exists (the mode given to writeFileSync applies only on creation).
 */
function writePrivate(path: string, text: string): void {
  const fd = openSync(path, 'w', 0o600);
  try {
    fchmodSync(fd, 0o600);
    writeFileSync(fd, text);
  } finally {
    closeSync(fd);
  }
}

const USAGE = `Usage: ${TOOL_NAME} [path] [options]

Shows what each AI agent in a repository can do and flags authority it does not need.
Reads files only: it never runs repository code. It makes no network calls unless you ask
for live evidence with --live or --agent-map-url, or for branch rules with --github-repo.

Output:
  --format <text|json|sarif|markdown|inventory>  Output format (default: text)
  --output <file>                      Write the report to a file instead of stdout
  --list-rules                         Print every rule and exit

Gating:
  --fail-on <severity|none>            Exit 1 at or above this severity (default: high, or fail_on in .agc.yaml)
  --min-confidence <high|low>          Let low-confidence findings fail the run (default: high)
  --base <git-ref>                     Compare with this commit; report only what the change made worse
  --baseline <file>                    Ignore findings listed in this baseline file
  --write-baseline <file>              Write current findings to a baseline file and exit 0

Evidence:
  --agent-guard <file>                 Agent Guard record to read: describe() output, an inventory
                                       snapshot or a host manifest (repeatable)
  --live                               Query the Agent Map named in agent_map in .agc.yaml (read-only)
  --agent-map-url <url>                Query this Agent Map (read-only); implies --live
                                       The token comes from AGENT_MAP_TOKEN (or agent_map.token_env,
                                       which must end in AGENT_MAP_TOKEN)
  --github-repo <owner/name>           Ask GitHub (read-only) whether the branch requires code-owner
                                       review; the token comes from GITHUB_TOKEN or GH_TOKEN
  --github-branch <branch>             The branch changes merge into (default: the default branch)
  --import-sarif <file>                Merge another tool's SARIF 2.1.0 findings (repeatable)
  --include-user                       Also read your own settings: ~/.claude, ~/.claude.json, ~/.codex,
                                       ~/.gemini and managed settings (local runs only, not in CI)

Fixing:
  --fix                                Apply safe fixes to agent settings and workflows, then report
  --fix-dry-run                        Print the fixes as a diff without writing

  --version                            Print the version
  --help                               Print this help

Exit codes: 0 no findings at or above --fail-on, 1 findings, 2 usage, read or live-evidence error.
`;

export interface CliIo {
  readonly stdout: (text: string) => void;
  readonly stderr: (text: string) => void;
  readonly cwd: string;
  /** Environment for the Agent Map token; defaults to process.env. */
  readonly env?: Readonly<Record<string, string | undefined>>;
  /** For tests; defaults to the global fetch. */
  readonly fetch?: typeof fetch;
  /** Home folder for --include-user; defaults to the user's home. For tests. */
  readonly home?: string;
}

class UsageError extends Error {}

/**
 * Reads a file named on the command line. Files in a checkout can be planted by the change under
 * review, so a link is refused and the type and size are checked on the open descriptor before reading.
 */
function readInput(path: string): string {
  let fd: number | undefined;
  try {
    fd = openSync(path, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0) | (constants.O_NONBLOCK ?? 0));
    const info = fstatSync(fd);
    if (!info.isFile()) throw new UsageError(`${path} is not a regular file`);
    if (info.size > MAX_INPUT_BYTES) throw new UsageError(`${path} is larger than ${MAX_INPUT_BYTES} bytes`);
    // Windows has no O_NOFOLLOW: confirm the opened file is the entry itself, not a link's target.
    const entry = lstatSync(path);
    if (entry.isSymbolicLink() || entry.ino !== info.ino || entry.dev !== info.dev)
      throw new UsageError(`${path} is a symbolic link; name the file itself`);
    return readFileSync(fd, 'utf8');
  } catch (error) {
    if (error instanceof UsageError) throw error;
    const code = (error as NodeJS.ErrnoException).code;
    if (code === 'ELOOP' || code === 'EMLINK') throw new UsageError(`${path} is a symbolic link; name the file itself`);
    throw new UsageError(`could not read ${path}${code ? ` (${code})` : ''}`);
  } finally {
    if (fd !== undefined) closeSync(fd);
  }
}

/** Parses `.agc.yaml` from a source; a parse error keeps its first line only, so file content is never echoed. */
function loadConfig(source: FileSource, ref?: string): { config: CheckConfig; text: string | undefined } {
  const text = source.readNamed('.agc.yaml');
  if (text === undefined) return { config: DEFAULT_CONFIG, text };
  try {
    return { config: parseConfig(text), text };
  } catch (error) {
    const first = (error instanceof Error ? error.message : String(error)).split(/\r?\n/)[0]!;
    throw new UsageError(`${ref ? `${ref}:` : ''}.agc.yaml: ${first.replace(/^\.agc\.yaml:?\s*/, '')}`);
  }
}

/** The repo-relative form of a path inside `root`, or undefined when it is outside. */
function insideRoot(root: string, path: string): string | undefined {
  const rel = relative(root, path);
  if (!rel || rel === '..' || rel.startsWith(`..${sep}`)) return undefined;
  return safeRelative(rel.split(sep).join('/'));
}

function listRules(): string {
  const rows = RULES.map(
    rule => `${rule.id.padEnd(13)} ${rule.severity.padEnd(8)} ${rule.mode.padEnd(11)} ${rule.title}`,
  );
  return `${['ID            Severity Evidence    Title', ...rows].join('\n')}\n\nDetails: ${RULES_URI}\n`;
}

/** Runs the CLI and resolves to the exit code. Exposed for tests. */
export async function runCli(argv: readonly string[], io: CliIo): Promise<number> {
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
        'agent-guard': { type: 'string', multiple: true },
        live: { type: 'boolean', default: false },
        'agent-map-url': { type: 'string' },
        'github-repo': { type: 'string' },
        'github-branch': { type: 'string' },
        'import-sarif': { type: 'string', multiple: true },
        fix: { type: 'boolean', default: false },
        'fix-dry-run': { type: 'boolean', default: false },
        'list-rules': { type: 'boolean', default: false },
        'include-user': { type: 'boolean', default: false },
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
  if (values['list-rules']) {
    io.stdout(listRules());
    return 0;
  }
  const usage = (message: string) => {
    io.stderr(`${message}\n`);
    return 2;
  };
  if (positionals.length > 1) return usage(`Expected at most one path.\n\n${USAGE}`);
  const format = values.format;
  if (!['text', 'json', 'sarif', 'markdown', 'inventory'].includes(format)) return usage(`Unknown format "${format}".`);
  const failOnFlag = values['fail-on'];
  if (failOnFlag !== undefined && failOnFlag !== 'none' && !SEVERITY_ORDER.includes(failOnFlag as never))
    return usage(`--fail-on must be one of ${[...SEVERITY_ORDER].reverse().join(', ')}, none.`);
  const minFlag = values['min-confidence'];
  if (minFlag !== undefined && minFlag !== 'high' && minFlag !== 'low')
    return usage('--min-confidence must be high or low.');
  if (values.fix && values['fix-dry-run']) return usage('Use --fix or --fix-dry-run, not both.');
  if (values['include-user'] && (values.fix || values['fix-dry-run']))
    return usage('--fix changes repository files only; run it without --include-user.');
  if (values['include-user'] && values['write-baseline'])
    return usage('--write-baseline records repository findings; run it without --include-user.');
  const env = io.env ?? process.env;
  if (values['include-user'] && env['CI'] && env['CI'] !== 'false' && env['CI'] !== '0')
    return usage('--include-user reads your own settings; it is for local runs, not CI.');
  if ((values.fix || values['fix-dry-run']) && values.base) return usage('--fix cannot be combined with --base.');
  if (values['github-branch'] !== undefined && !values['github-repo'])
    return usage('--github-branch needs --github-repo.');
  if (values['github-repo'] !== undefined && !isRepoName(values['github-repo']))
    return usage('--github-repo must be owner/name.');

  const root = resolve(io.cwd, positionals[0] ?? '.');
  try {
    // With --base, the change under review must not set its own gate: .agc.yaml and an in-repo
    // baseline are read from the base commit, so an edit to either takes effect once merged.
    const baseSource = values.base ? new GitSource(root, values.base) : undefined;
    const working = loadConfig(new DirectorySource(root));
    if (working.text === undefined && lstatSync(resolve(root, '.agc.yaml'), { throwIfNoEntry: false }))
      io.stderr('note: .agc.yaml is not a plain file under 1 MiB (a link, a device or too large); it was not read.\n');
    const { config } = baseSource ? loadConfig(baseSource, values.base) : working;
    if (baseSource && working.text !== baseSource.readNamed('.agc.yaml'))
      io.stderr(`note: .agc.yaml differs from ${values.base}; the version at ${values.base} is used.\n`);
    let baseline = new Set<string>();
    if (values.baseline) {
      const path = resolve(io.cwd, values.baseline);
      const inRepo = baseSource ? insideRoot(root, path) : undefined;
      if (baseSource && inRepo !== undefined) {
        const text = baseSource.readNamed(inRepo);
        if (text === undefined) io.stderr(`note: ${inRepo} is not in ${values.base}; no baseline applied.\n`);
        else baseline = parseBaseline(text);
        if (text !== undefined && text !== new DirectorySource(root).readNamed(inRepo))
          io.stderr(`note: ${inRepo} differs from ${values.base}; the version at ${values.base} is used.\n`);
      } else baseline = parseBaseline(readInput(path));
    }
    const agentGuardFiles: TextFile[] = (values['agent-guard'] ?? []).map(path => ({
      path: safeRelative(path) ?? path,
      text: readInput(resolve(io.cwd, path)),
    }));
    const imported: Finding[] = (values['import-sarif'] ?? []).flatMap(path =>
      importSarif(readInput(resolve(io.cwd, path)), path),
    );

    let live: LiveEvidence | undefined;
    if (values.live || values['agent-map-url']) {
      const url = values['agent-map-url'] ?? config.agentMap?.url;
      if (!url) return usage('--live needs agent_map.url in .agc.yaml, or --agent-map-url.');
      let parsedUrl: URL;
      try {
        parsedUrl = new URL(url);
      } catch {
        return usage(`--agent-map-url is not a URL.`);
      }
      const local = /^(localhost|127\.\d+\.\d+\.\d+|\[::1\])$/.test(parsedUrl.hostname);
      if (parsedUrl.protocol !== 'https:' && !(parsedUrl.protocol === 'http:' && local))
        return usage('The Agent Map URL must use https (http only for localhost).');
      if (parsedUrl.username || parsedUrl.password || parsedUrl.search)
        return usage('Put the Agent Map token in the environment, never in the URL.');
      // parseConfig only accepts a token variable whose name ends in AGENT_MAP_TOKEN, so the
      // repository cannot choose which secret is sent.
      const tokenEnv = config.agentMap?.tokenEnv ?? 'AGENT_MAP_TOKEN';
      const token = env[tokenEnv];
      if (!token) return usage(`Live evidence needs a read-only Agent Map token in ${tokenEnv}.`);
      try {
        live = await fetchLiveEvidence({
          url: parsedUrl.href.replace(/\/$/, ''),
          token,
          ...(io.fetch ? { fetch: io.fetch } : {}),
        });
      } catch (error) {
        if (error instanceof AgentMapError) {
          io.stderr(`${TOOL_NAME}: ${error.message.replaceAll(token, '[token]')}\n`);
          return 2;
        }
        throw error;
      }
    }

    let github: BranchRules | undefined;
    if (values['github-repo']) {
      const token = env['GITHUB_TOKEN'] || env['GH_TOKEN'] || undefined;
      try {
        github = await fetchBranchRules({
          repo: values['github-repo'],
          ...(values['github-branch'] ? { branch: values['github-branch'] } : {}),
          ...(token ? { token } : {}),
          ...(env['GITHUB_API_URL'] ? { apiUrl: env['GITHUB_API_URL'] } : {}),
          ...(io.fetch ? { fetch: io.fetch } : {}),
        });
      } catch (error) {
        if (!(error instanceof GitHubError)) throw error;
        // Branch rules add one low-severity check; a GitHub outage should not fail the scan.
        const message = token ? error.message.replaceAll(token, '[token]') : error.message;
        io.stderr(oneLine(`warning: ${message}; code-owner enforcement (AGC-GOV-004) was not checked.`) + '\n');
      }
    }

    const options: Omit<ScanOptions, 'root'> = {
      config,
      baseline,
      agentGuardFiles,
      imported,
      ...(live ? { live } : {}),
      ...(github ? { github } : {}),
      ...(values['include-user']
        ? {
            userFiles: readUserConfig(io.home ?? homedir(), process.platform, path =>
              io.stderr(
                `${TOOL_NAME}: ${path} was not read (larger than 1 MiB, or not a readable file); settings in it are not in this report.\n`,
              ),
            ),
          }
        : {}),
    };
    let head = scan({ root, ...options });

    if (values.fix || values['fix-dry-run']) {
      const source = new DirectorySource(root);
      const plan = planFixes(head, source, overlay => scan({ root, ...options, source: overlay }));
      const diffs = plan.edits.map(formatDiff).join('');
      if (values['fix-dry-run']) {
        io.stdout(diffs || 'No safe fixes to apply.\n');
        for (const skip of plan.skipped)
          io.stderr(oneLine(`not fixed: ${skip.finding.ruleId} ${skip.finding.location.file}: ${skip.reason}`) + '\n');
        return 0;
      }
      for (const edit of plan.edits) {
        const target = resolve(root, ...edit.path.split('/'));
        // Re-check the file did not change while planning: never overwrite someone's edit.
        if (readFileSync(target, 'utf8') !== edit.before) throw new UsageError(`${edit.path} changed during --fix`);
        writeFileSync(target, edit.after);
        for (const item of edit.fixed)
          io.stderr(oneLine(`fixed: ${item.ruleId} ${edit.path}: ${item.description}`) + '\n');
      }
      for (const skip of plan.skipped)
        io.stderr(oneLine(`not fixed: ${skip.finding.ruleId} ${skip.finding.location.file}: ${skip.reason}`) + '\n');
      if (plan.edits.length) head = scan({ root, ...options });
    }

    if (values['write-baseline']) {
      writePrivate(
        resolve(io.cwd, values['write-baseline']),
        formatBaseline([...head.findings, ...head.suppressed.map(s => s.finding)]),
      );
      io.stdout(
        `Wrote ${head.findings.length + head.suppressed.length} fingerprint(s) to ${values['write-baseline']}.\n`,
      );
      return 0;
    }
    let diff: ScanDiff | undefined;
    // The base is read from git with the same evidence: live and imported findings are not "new".
    if (baseSource) diff = diffScans(scan({ root, ...options, source: baseSource }), head);
    const report = render(format, head, diff);
    if (values.output) writePrivate(resolve(io.cwd, values.output), report);
    else io.stdout(report);
    for (const error of head.errors)
      io.stderr(oneLine(`warning: could not read ${error.file}: ${error.message}`) + '\n');
    const failOn = (failOnFlag ?? config.failOn) as FailOn;
    const minConfidence = (minFlag ?? config.minConfidence) as Confidence;
    return shouldFail(diff ? diff.added : head.findings, failOn, minConfidence) ? 1 : 0;
  } catch (error) {
    io.stderr(oneLine(`${TOOL_NAME}: ${error instanceof Error ? error.message : String(error)}`) + '\n');
    return 2;
  }
}

function render(format: string, result: ScanResult, diff: ScanDiff | undefined): string {
  if (format === 'json') return formatJson(result, diff);
  if (format === 'sarif') return formatSarif(result, diff ? diff.added : result.findings);
  if (format === 'markdown') return formatMarkdown(result, diff);
  if (format === 'inventory') return formatInventory(result);
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
  runCli(process.argv.slice(2), {
    stdout: text => process.stdout.write(text),
    stderr: text => process.stderr.write(text),
    cwd: process.cwd(),
  }).then(
    code => {
      process.exitCode = code;
    },
    error => {
      process.stderr.write(`${TOOL_NAME}: ${error instanceof Error ? error.message : String(error)}\n`);
      process.exitCode = 2;
    },
  );
}
