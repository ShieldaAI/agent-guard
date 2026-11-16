import type { Finding, ScanResult } from './types.js';
import { SEVERITY_ORDER } from './types.js';
import type { FileSource } from './source.js';
import { isRecord } from './text.js';

/**
 * Safe, local fixes. Each candidate edit is checked by scanning the edited files again: it is
 * kept only if its finding disappears and no finding of the same or higher severity appears.
 * Fixes never add authority, never touch files other than agent settings and workflows, and
 * never rewrite a JSON file that holds comments.
 */

export interface FileEdit {
  readonly path: string;
  readonly before: string;
  readonly after: string;
  readonly fixed: readonly { readonly ruleId: string; readonly fingerprint: string; readonly description: string }[];
}

export interface FixPlan {
  readonly edits: readonly FileEdit[];
  /** Findings a fix was tried for but not kept, with the reason. */
  readonly skipped: readonly { readonly finding: Finding; readonly reason: string }[];
}

type Candidate = { readonly description: string; readonly apply: (text: string) => string | undefined };

/** Rules whose finding points at one `permissions.allow` entry, fixed by moving it to `ask`. */
const ALLOW_RULES = new Set([
  'AGC-PERM-002',
  'AGC-PERM-003',
  'AGC-PERM-004',
  'AGC-PERM-005',
  'AGC-PER-001',
  'AGC-PER-002',
  'AGC-TRI-001',
]);

const DEFAULT_TURNS = 30;
const DEFAULT_TIMEOUT = 30;

function indentOf(text: string): string | number {
  const match = /\n([ \t]+)"/.exec(text);
  if (!match) return 2;
  return match[1]!.includes('\t') ? '\t' : match[1]!.length;
}

/** Rewrites a strict-JSON settings file; undefined when it is not strict JSON (comments, trailing commas). */
function editJson(text: string, change: (data: Record<string, unknown>) => boolean): string | undefined {
  let data: unknown;
  try {
    data = JSON.parse(text);
  } catch {
    return undefined;
  }
  if (!isRecord(data) || !change(data)) return undefined;
  return `${JSON.stringify(data, null, indentOf(text))}${text.endsWith('\n') ? '\n' : ''}`;
}

/** The allow entry written on a given line of a settings file, if there is exactly one. */
function allowEntryAt(text: string, line: number): string | undefined {
  const source = text.split('\n')[line - 1];
  if (source === undefined) return undefined;
  const strings = [...source.matchAll(/"((?:[^"\\]|\\.)*)"/g)].map(match => JSON.parse(`"${match[1]}"`) as string);
  return strings.length === 1 ? strings[0] : undefined;
}

function moveToAsk(entry: string): Candidate {
  return {
    description: `move "${entry}" from permissions.allow to permissions.ask`,
    apply: text =>
      editJson(text, data => {
        const permissions = data['permissions'];
        if (!isRecord(permissions) || !Array.isArray(permissions['allow'])) return false;
        const allow = permissions['allow'] as unknown[];
        if (!allow.includes(entry)) return false;
        permissions['allow'] = allow.filter(item => item !== entry);
        const ask = Array.isArray(permissions['ask']) ? (permissions['ask'] as unknown[]) : [];
        if (!ask.includes(entry)) ask.push(entry);
        permissions['ask'] = ask;
        return true;
      }),
  };
}

const NO_BYPASS: Candidate = {
  description: 'set permissions.defaultMode to "default" instead of "bypassPermissions"',
  apply: text =>
    editJson(text, data => {
      const permissions = data['permissions'];
      if (isRecord(permissions) && permissions['defaultMode'] === 'bypassPermissions') {
        permissions['defaultMode'] = 'default';
        return true;
      }
      if (data['defaultMode'] === 'bypassPermissions') {
        data['defaultMode'] = 'default';
        return true;
      }
      return false;
    }),
};

function lines(text: string): string[] {
  return text.split('\n');
}

const SKIP_FLAGS = /\s*--(?:dangerously-skip-permissions|permission-mode[ =]bypassPermissions)\b/;

function dropSkipFlag(line: number): Candidate {
  return {
    description: 'remove the permission-bypass flag from the agent step',
    apply: text => {
      const all = lines(text);
      const current = all[line - 1];
      if (current === undefined || !SKIP_FLAGS.test(current)) return undefined;
      all[line - 1] = current.replace(SKIP_FLAGS, '');
      return all.join('\n');
    },
  };
}

/** The step's key indentation: the column of the key after `- `, or of the key itself. */
function stepKeyIndent(line: string): string | undefined {
  const match = /^(\s*)(- )?\w/.exec(line);
  if (!match) return undefined;
  return match[1]! + (match[2] ? '  ' : '');
}

function addStepTimeout(line: number): Candidate {
  return {
    description: `add timeout-minutes: ${DEFAULT_TIMEOUT} to the agent step`,
    apply: text => {
      const all = lines(text);
      const indent = stepKeyIndent(all[line - 1] ?? '');
      if (indent === undefined) return undefined;
      all.splice(line, 0, `${indent}timeout-minutes: ${DEFAULT_TIMEOUT}`);
      return all.join('\n');
    },
  };
}

function addMaxTurns(line: number): Candidate {
  return {
    description: `add --max-turns ${DEFAULT_TURNS} to the agent's claude_args`,
    apply: text => {
      const all = lines(text);
      const indent = stepKeyIndent(all[line - 1] ?? '');
      if (indent === undefined) return undefined;
      // Find the step's `with:` block: the next line at the step's key indent that says `with:`.
      let end = all.length;
      let withLine = -1;
      for (let i = line; i < all.length; i += 1) {
        const current = all[i]!;
        if (!current.trim() || current.trim().startsWith('#')) continue;
        const lead = /^\s*/.exec(current)![0];
        if (lead.length < indent.length || (lead.length === indent.length - 2 && current.trim().startsWith('- '))) {
          end = i;
          break;
        }
        if (lead === indent && /^with:\s*$/.test(current.trim())) withLine = i;
      }
      if (withLine < 0) return undefined;
      let childIndent: string | undefined;
      for (let i = withLine + 1; i < end; i += 1) {
        const current = all[i]!;
        if (!current.trim()) continue;
        const lead = /^\s*/.exec(current)![0];
        if (lead.length <= indent.length) break;
        childIndent ??= lead;
        if (lead !== childIndent) continue;
        const args = /^(\s*claude_args:\s*)(["']?)([^"'|>]*)\2\s*$/.exec(current);
        if (args) {
          all[i] =
            `${args[1]}${args[2]}${args[3]!.trimEnd()}${args[3]!.trim() ? ' ' : ''}--max-turns ${DEFAULT_TURNS}${args[2]}`;
          return all.join('\n');
        }
        if (/^\s*claude_args:/.test(current)) return undefined; // block scalar: leave it to a person
      }
      all.splice(withLine + 1, 0, `${childIndent ?? `${indent}  `}claude_args: --max-turns ${DEFAULT_TURNS}`);
      return all.join('\n');
    },
  };
}

function candidateFor(finding: Finding, text: string): Candidate | undefined {
  const path = finding.location.file;
  const settings = /(^|\/)\.claude\/settings(\.local)?\.json$/.test(path);
  const workflow = /^\.github\/workflows\/[^/]+\.ya?ml$/.test(path);
  if (settings && ALLOW_RULES.has(finding.ruleId)) {
    const entry = allowEntryAt(text, finding.location.line);
    return entry === undefined ? undefined : moveToAsk(entry);
  }
  if (settings && finding.ruleId === 'AGC-PERM-001') return NO_BYPASS;
  if (workflow && finding.ruleId === 'AGC-PERM-001') return dropSkipFlag(finding.location.line);
  if (workflow && finding.ruleId === 'AGC-LIM-002') return addStepTimeout(finding.location.line);
  if (workflow && finding.ruleId === 'AGC-LIM-001') return addMaxTurns(finding.location.line);
  return undefined;
}

/** A source that returns edited text for some paths and the original for the rest. */
export class OverlaySource implements FileSource {
  constructor(
    private readonly base: FileSource,
    private readonly files: ReadonlyMap<string, string>,
  ) {}
  get label(): string {
    return this.base.label;
  }
  get skipped(): number {
    return this.base.skipped;
  }
  list(): readonly string[] {
    return this.base.list();
  }
  read(path: string): string | undefined {
    return this.files.get(path) ?? this.base.read(path);
  }
  readNamed(path: string): string | undefined {
    return this.files.get(path) ?? this.base.readNamed(path);
  }
}

const rank = (finding: Finding) => SEVERITY_ORDER.indexOf(finding.severity);

/**
 * Plans fixes for `result`. `rescan` scans a source with the same options as the original scan.
 * Each edit is kept only if it removes its finding without adding one of equal or higher severity.
 */
export function planFixes(result: ScanResult, source: FileSource, rescan: (source: FileSource) => ScanResult): FixPlan {
  const current = new Map<string, string>();
  const fixed = new Map<string, { ruleId: string; fingerprint: string; description: string }[]>();
  const skipped: { finding: Finding; reason: string }[] = [];
  let baseline = result;
  for (const original of result.findings) {
    // Earlier edits move lines: use the finding as the latest scan reports it.
    const finding = baseline.findings.find(item => item.fingerprint === original.fingerprint);
    if (!finding) continue; // fixed by an earlier edit
    const path = finding.location.file;
    const text = current.get(path) ?? source.read(path);
    if (text === undefined) continue;
    const candidate = candidateFor(finding, text);
    if (!candidate) continue;
    const after = candidate.apply(text);
    if (after === undefined || after === text) {
      skipped.push({ finding, reason: 'the file is not in a shape the fixer edits safely (comments, block scalars)' });
      continue;
    }
    const trial = new Map(current).set(path, after);
    const next = rescan(new OverlaySource(source, trial));
    const known = new Set(baseline.findings.map(item => item.fingerprint));
    const worse = next.findings.filter(item => !known.has(item.fingerprint) && rank(item) >= rank(finding));
    const gone = !next.findings.some(item => item.fingerprint === finding.fingerprint);
    if (!gone || worse.length || next.errors.length > baseline.errors.length) {
      skipped.push({
        finding,
        reason: !gone
          ? 'the edit did not remove the finding'
          : worse.length
            ? `the edit would add ${worse[0]!.ruleId}`
            : 'the edited file no longer parses',
      });
      continue;
    }
    current.set(path, after);
    baseline = next;
    const list = fixed.get(path) ?? [];
    list.push({ ruleId: finding.ruleId, fingerprint: finding.fingerprint, description: candidate.description });
    fixed.set(path, list);
  }
  const edits = [...current].map(([path, after]) => ({
    path,
    before: source.read(path) ?? '',
    after,
    fixed: fixed.get(path) ?? [],
  }));
  return { edits, skipped };
}

/** A unified diff of one edit, for review before writing. */
export function formatDiff(edit: FileEdit): string {
  const a = edit.before.split('\n');
  const b = edit.after.split('\n');
  // Longest common subsequence on lines; settings and workflow files are small.
  const n = a.length;
  const m = b.length;
  if (n * m > 4_000_000) return `--- a/${edit.path}\n+++ b/${edit.path}\n@@ file too large to diff @@\n`;
  const table: Uint32Array[] = Array.from({ length: n + 1 }, () => new Uint32Array(m + 1));
  for (let i = n - 1; i >= 0; i -= 1)
    for (let j = m - 1; j >= 0; j -= 1)
      table[i]![j] = a[i] === b[j] ? table[i + 1]![j + 1]! + 1 : Math.max(table[i + 1]![j]!, table[i]![j + 1]!);
  const ops: { kind: ' ' | '-' | '+'; text: string; ai: number; bi: number }[] = [];
  let i = 0;
  let j = 0;
  while (i < n || j < m) {
    if (i < n && j < m && a[i] === b[j]) {
      ops.push({ kind: ' ', text: a[i]!, ai: i, bi: j });
      i += 1;
      j += 1;
    } else if (j < m && (i === n || table[i]![j + 1]! >= table[i + 1]![j]!)) {
      ops.push({ kind: '+', text: b[j]!, ai: i, bi: j });
      j += 1;
    } else {
      ops.push({ kind: '-', text: a[i]!, ai: i, bi: j });
      i += 1;
    }
  }
  const out = [`--- a/${edit.path}`, `+++ b/${edit.path}`];
  const context = 3;
  let k = 0;
  while (k < ops.length) {
    if (ops[k]!.kind === ' ') {
      k += 1;
      continue;
    }
    const start = Math.max(0, k - context);
    let end = k;
    let quiet = 0;
    while (end < ops.length && quiet <= context * 2) {
      quiet = ops[end]!.kind === ' ' ? quiet + 1 : 0;
      end += 1;
    }
    end = Math.min(ops.length, end - Math.max(0, quiet - context));
    const hunk = ops.slice(start, end);
    const aStart = hunk[0]!.ai + 1;
    const bStart = hunk[0]!.bi + 1;
    const aCount = hunk.filter(op => op.kind !== '+').length;
    const bCount = hunk.filter(op => op.kind !== '-').length;
    out.push(`@@ -${aStart},${aCount} +${bStart},${bCount} @@`);
    for (const op of hunk) out.push(`${op.kind}${op.text}`);
    k = end;
  }
  return `${out.join('\n')}\n`;
}
