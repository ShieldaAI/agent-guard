import { spawnSync } from 'node:child_process';
import { existsSync, realpathSync, statSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { DEFAULT_CONFIG, parseConfig, shouldFail, type CheckConfig, type FailOn } from './config.js';
import { diffScans, scan } from './scan.js';
import { DirectorySource, type FileSource } from './source.js';
import { SEVERITY_ORDER, type Confidence, type Finding } from './types.js';
import type { TextFile } from './model.js';
import { oneLine } from './text.js';

/**
 * Hook mode: run from a Claude Code hook (SessionStart or UserPromptSubmit) on a developer's machine.
 *
 * Claude Code merges the repository's `.claude/settings.json` with files no pull request shows: the
 * gitignored `.claude/settings.local.json`, the developer's `~/.claude` settings and managed
 * settings. The hook scans the folder on disk plus those files, and compares it with the files git
 * tracks as they are staged, which is what a pull request will show and CI judge. Only what the
 * comparison adds is reported, so a passed review date or a finding CI already accepted does not
 * interrupt anyone, while an unstaged or hidden (`--skip-worktree`) edit to a tracked file does.
 *
 * Exit codes follow Claude Code's hook contract: 0 and no output when nothing is added; 2 with the
 * findings on stderr when something is (SessionStart shows it to the developer and the session goes
 * on; UserPromptSubmit blocks the prompt); 1 when the hook itself fails, which never blocks.
 */

export interface HookOptions {
  readonly root: string;
  readonly event: string;
  readonly userFiles: readonly TextFile[];
  /** Personal settings files that exist but could not be read (too large, not a regular file). */
  readonly unreadUserFiles?: readonly string[];
  readonly failOn?: FailOn;
  readonly minConfidence?: Confidence;
  /** The clock for review dates (tests). */
  readonly now?: number;
}

export interface HookResult {
  /** 0 nothing added (stderr may name files it could not read), 2 findings added (stderr carries them). */
  readonly code: 0 | 2;
  readonly message: string;
  readonly findings: readonly Finding[];
  /** What the session was compared with: staged tracked files, or (outside git) the folder without local files. */
  readonly comparedWith: 'tracked files' | 'shared files';
}

const MAX_SHOWN = 5;

/** Files Claude Code reads for one developer only: gitignored by default, never in a pull request. */
const LOCAL_ONLY = /(^|\/)(\.claude\/settings\.local\.json|CLAUDE\.local\.md)$/;

const GIT_ENV = { ...process.env, GIT_CONFIG_NOSYSTEM: '1', GIT_TERMINAL_PROMPT: '0' };

/**
 * `base` limited to the paths `keep` accepts. `staged`, when given, supplies a file's content in
 * place of the disk (`null`: no such file there). Every report of the walk (skipped, linked, case
 * variants) is limited the same way, so a note about a shared file is in both scans and never counts
 * as local.
 */
class FilteredSource implements FileSource {
  constructor(
    private readonly base: FileSource,
    private readonly keep: (path: string) => boolean,
    private readonly staged?: (path: string) => string | null | undefined,
  ) {}
  get label(): string {
    return this.base.label;
  }
  get skipped(): number {
    return this.base.skipped;
  }
  get skippedFiles(): readonly string[] {
    return (this.base.skippedFiles ?? []).filter(this.keep);
  }
  get linkedFiles(): readonly string[] {
    return (this.base.linkedFiles ?? []).filter(this.keep);
  }
  get skippedConfig(): readonly string[] {
    return (this.base.skippedConfig ?? []).filter(this.keep);
  }
  get caseVariants(): readonly string[] {
    return (this.base.caseVariants ?? []).filter(this.keep);
  }
  get caseCollisions(): readonly (readonly [string, string])[] {
    return (this.base.caseCollisions ?? []).filter(([a, b]) => this.keep(a) && this.keep(b));
  }
  get truncated(): boolean {
    return this.base.truncated ?? false;
  }
  list(): readonly string[] {
    return this.base.list().filter(this.keep);
  }
  read(path: string): string | undefined {
    return this.#read(path, () => this.base.read(path));
  }
  readNamed(path: string): string | undefined {
    return this.#read(path, () => this.base.readNamed(path));
  }
  #read(path: string, fromDisk: () => string | undefined): string | undefined {
    if (!this.keep(path)) return undefined;
    const staged = this.staged?.(path);
    return staged === null ? undefined : (staged ?? fromDisk());
  }
}

/**
 * The event and folder from the JSON Claude Code writes to a hook's stdin. Input cut short (a prompt
 * over the read limit) still names its event: the fields are found in the text before the prompt.
 */
export function parseHookInput(text: string | undefined): { event?: string; cwd?: string } {
  if (!text?.trim()) return {};
  let record: Record<string, unknown> | undefined;
  try {
    const value: unknown = JSON.parse(text);
    if (typeof value === 'object' && value !== null) record = value as Record<string, unknown>;
  } catch {
    const head = text.slice(0, 64 * 1024);
    const field = (name: string): string | undefined => {
      const match = new RegExp(`"${name}"\\s*:\\s*("(?:[^"\\\\\\n]|\\\\.)*")`).exec(head);
      try {
        return match ? (JSON.parse(match[1]!) as string) : undefined;
      } catch {
        return undefined;
      }
    };
    record = { hook_event_name: field('hook_event_name'), cwd: field('cwd') };
  }
  if (!record) return {};
  return {
    ...(typeof record['hook_event_name'] === 'string' ? { event: record['hook_event_name'] } : {}),
    ...(typeof record['cwd'] === 'string' ? { cwd: record['cwd'] } : {}),
  };
}

function git(root: string, args: string[], input?: string): Buffer | undefined {
  const result = spawnSync('git', ['-C', root, ...args], {
    maxBuffer: 256 * 1024 * 1024,
    env: GIT_ENV,
    ...(input === undefined ? {} : { input }),
  });
  return result.error || result.status !== 0 ? undefined : result.stdout;
}

interface Tracked {
  /** Tracked paths under `root` and the folders that hold them (the walk reports some folders). */
  readonly paths: Set<string>;
  /**
   * Staged object of each tracked file whose index content stands for what is on disk: a regular
   * file, outside a submodule, with no clean/smudge filter. Others are compared as they are on disk.
   */
  readonly objects: Map<string, string>;
}

/**
 * What git tracks under `root`, submodules included. Undefined outside a work tree, and when nothing
 * under `root` is tracked (a folder its parent repository ignores, or a repo with nothing added
 * yet), where everything would otherwise look local.
 */
function trackedFiles(root: string): Tracked | undefined {
  const out = git(root, ['ls-files', '-z', '--stage', '--recurse-submodules']);
  if (!out) return undefined;
  const paths = new Set<string>();
  const regular = new Map<string, string>();
  for (const entry of out.toString('utf8').split('\0')) {
    const match = /^(\d{6}) ([0-9a-f]+) \d\t([^]+)$/.exec(entry);
    if (!match) continue;
    const [, mode, object, path] = match;
    paths.add(path!);
    const parts = path!.split('/');
    for (let depth = 1; depth < parts.length; depth++) paths.add(parts.slice(0, depth).join('/'));
    // A link's blob is its target's name, not the settings it points to.
    if (mode === '100644' || mode === '100755') regular.set(path!, object!);
  }
  if (!paths.size) return undefined;
  // Objects of a submodule are not in this repository: `cat-file` cannot read them (left to disk).
  // A filtered file (LFS, git-crypt) is staged in its clean form: compared as it is on disk.
  const filtered = new Set<string>();
  const names = [...regular.keys()];
  const attrs = names.length
    ? git(root, ['check-attr', '-z', '--stdin', 'filter'], names.join('\0') + '\0')
    : undefined;
  if (attrs) {
    const fields = attrs.toString('utf8').split('\0');
    for (let i = 0; i + 2 < fields.length; i += 3)
      if (fields[i + 2] !== 'unspecified' && fields[i + 2] !== 'unset') filtered.add(fields[i]!);
  } else if (names.length) for (const name of names) filtered.add(name); // Unknown: trust the disk.
  for (const name of filtered) regular.delete(name);
  return { paths, objects: regular };
}

/** The content of staged objects by id, in one `git cat-file --batch` (ids, so no path is parsed). */
function readObjects(root: string, objects: readonly string[]): Map<string, string> {
  const out = new Map<string, string>();
  const unique = [...new Set(objects)];
  if (!unique.length) return out;
  const batch = git(root, ['cat-file', '--batch'], unique.map(id => `${id}\n`).join(''));
  if (!batch) return out;
  let at = 0;
  for (const id of unique) {
    const end = batch.indexOf(0x0a, at);
    if (end < 0) break;
    const match = /^([0-9a-f]+) (\w+) (\d+)$/.exec(batch.subarray(at, end).toString('utf8'));
    at = end + 1;
    if (!match) continue; // `missing`: a submodule's object.
    const size = Number(match[3]);
    if (match[1] === id && match[2] === 'blob') out.set(id, batch.subarray(at, at + size).toString('utf8'));
    at += size + 1;
  }
  return out;
}

/** Paths Claude Code reads for the project at `root`: never another checkout's, whatever sits there. */
// A `.claude/` path with another `.claude/` below it (`.claude/worktrees/x/.claude/…`) is not one.
const PROJECT_OWN = /^(\.claude\/(?!(.*\/)?\.claude\/)|\.mcp\.json$|CLAUDE(\.local)?\.md$)/;

/**
 * Whether an untracked `path` belongs to another checkout inside the folder (a nested clone or a
 * worktree): a folder above it that git itself names as the top of a work tree.
 */
function inNestedRepo(root: string, path: string, seen: Map<string, boolean>): boolean {
  if (PROJECT_OWN.test(path)) return false;
  const parts = path.split('/').slice(0, -1);
  for (let depth = 1; depth <= parts.length; depth++) {
    const dir = parts.slice(0, depth).join('/');
    let nested = seen.get(dir);
    if (nested === undefined) {
      const top = existsSync(join(root, dir, '.git'))
        ? git(join(root, dir), ['rev-parse', '--show-toplevel'])?.toString('utf8').trim()
        : undefined;
      nested = top !== undefined && realpathOrSelf(top) === realpathOrSelf(join(root, dir));
      seen.set(dir, nested);
    }
    if (nested) return true;
  }
  return false;
}

function realpathOrSelf(path: string): string {
  try {
    return realpathSync(path);
  } catch {
    return path;
  }
}

/** Settings outside the repository that a Claude Code session reads (not Codex's or Gemini's). */
export function isClaudeUserFile(file: TextFile | string): boolean {
  return !/^~\/\.(codex|gemini)\//.test(typeof file === 'string' ? file : file.path);
}

function configFrom(source: FileSource): CheckConfig {
  const text = source.readNamed('.agc.yaml');
  if (text === undefined) return DEFAULT_CONFIG;
  try {
    return parseConfig(text);
  } catch {
    // A broken .agc.yaml is CI's to report; the hook keeps the defaults rather than failing a session.
    return DEFAULT_CONFIG;
  }
}

const rank = (finding: Finding) => SEVERITY_ORDER.indexOf(finding.severity);

export function runHook(options: HookOptions): HookResult {
  const root = resolve(options.root);
  // A wrong project folder must say so: scanning nothing would report a clean session.
  if (!statSync(root, { throwIfNoEntry: false })?.isDirectory()) throw new Error(`${root} is not a folder`);
  const tracked = trackedFiles(root);
  const disk = new DirectorySource(root);
  let shared: FileSource;
  let session: FileSource = disk;
  if (tracked) {
    // Configuration files as staged, in one git call; files a scan names later (hook scripts,
    // records) are read when asked for. A tracked file with no staged object here is read from disk.
    const staged = readObjects(
      root,
      disk.list().flatMap(path => tracked.objects.get(path) ?? []),
    );
    const stagedOf = (path: string): string | undefined => {
      const id = tracked.objects.get(path);
      if (id === undefined) return undefined;
      if (!staged.has(id)) for (const [key, text] of readObjects(root, [id])) staged.set(key, text);
      return staged.get(id);
    };
    shared = new FilteredSource(disk, path => tracked.paths.has(path), stagedOf);
    // A clone or worktree inside the folder is another checkout: its settings are not this session's.
    const seen = new Map<string, boolean>();
    session = new FilteredSource(disk, path => tracked.paths.has(path) || !inNestedRepo(root, path, seen));
  } else {
    shared = new FilteredSource(disk, path => !LOCAL_ONLY.test(path));
  }
  // The gate is the staged one: an unstaged or untracked edit to .agc.yaml cannot quiet the hook.
  const config = configFrom(shared);
  const clock = options.now === undefined ? {} : { now: options.now };
  const base = scan({ root, config, source: shared, ...clock });
  const head = scan({ root, config, source: session, userFiles: options.userFiles.filter(isClaudeUserFile), ...clock });
  const diff = diffScans(base, head);
  // Only what the session adds: findings the shared files already had (a passed review date, a
  // finding CI accepted) are CI's, even where diffScans counts them as new on every change.
  const before = new Map(base.findings.map(finding => [finding.fingerprint, rank(finding)]));
  const added = diff.added.filter(finding => rank(finding) > (before.get(finding.fingerprint) ?? -1));
  const failOn = options.failOn ?? (config.failOn as FailOn);
  const minConfidence = options.minConfidence ?? (config.minConfidence as Confidence);
  const shown = added.filter(finding => shouldFail([finding], failOn, minConfidence));
  const comparedWith = tracked ? 'tracked files' : 'shared files';
  const unread = (options.unreadUserFiles ?? []).filter(path => isClaudeUserFile(path));
  const unreadLine = unread.length
    ? oneLine(`  Not read (too large, or not a regular file): ${unread.join(', ')}.`)
    : undefined;
  if (!shown.length)
    // Nothing to hold the session for; a file it could not read is still said (stderr, exit 0).
    return {
      code: 0,
      message: unreadLine ? `Agent Guard Check:${unreadLine.slice(1)}\n` : '',
      findings: [],
      comparedWith,
    };

  const blocking = options.event === 'UserPromptSubmit';
  const what = tracked
    ? 'settings no pull request shows (local files, your own or managed settings, unstaged edits)'
    : 'settings only this machine has (local files, your own or managed settings)';
  const lines = [`Agent Guard Check: ${what} give this agent more authority than the repository reviewed:`];
  for (const finding of shown.slice(0, MAX_SHOWN)) {
    lines.push(
      oneLine(
        `  ${finding.severity.toUpperCase()} ${finding.ruleId} ${finding.location.file}:${finding.location.line}: ${finding.message}`,
      ),
    );
    if (finding.fix) lines.push(oneLine(`    Fix: ${finding.fix}`));
  }
  if (shown.length > MAX_SHOWN) lines.push(`  ...and ${shown.length - MAX_SHOWN} more.`);
  if (unreadLine) lines.push(unreadLine);
  lines.push(
    blocking
      ? 'Prompts are held until this is fixed. Run agent-guard-check --include-user for the full report.'
      : 'Run agent-guard-check --include-user for the full report.',
  );
  return { code: 2, message: `${lines.join('\n')}\n`, findings: shown, comparedWith };
}
