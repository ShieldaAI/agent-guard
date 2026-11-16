import { spawnSync } from 'node:child_process';
import { lstatSync, readdirSync, readFileSync } from 'node:fs';
import { join, relative, sep } from 'node:path';

/** Files larger than this are skipped: agent config is small, and a huge file is not worth parsing. */
export const MAX_FILE_BYTES = 1_048_576;
/** The walk stops after visiting this many directory entries. */
export const MAX_ENTRIES = 200_000;
const MAX_DEPTH = 12;
const SKIPPED_DIRECTORIES = new Set([
  '.git',
  'node_modules',
  'dist',
  'build',
  'out',
  'vendor',
  'target',
  'coverage',
  '.venv',
  'venv',
  '__pycache__',
  '.next',
  '.turbo',
]);

/** A read-only view of the files at one commit or in one directory. Paths are POSIX and relative. */
export interface FileSource {
  readonly label: string;
  list(): readonly string[];
  read(path: string): string | undefined;
  /**
   * Reads one file the config names explicitly, even if it is not a candidate. The same limits
   * apply: no symbolic links, no paths outside the root, at most 1 MiB.
   */
  readNamed(path: string): string | undefined;
  readonly skipped: number;
}

/** A repo-relative path with no `..`, no absolute prefix and no empty segment; undefined otherwise. */
export function safeRelative(path: string): string | undefined {
  const clean = path.replace(/\\/g, '/').replace(/^\.\//, '');
  const parts = clean.split('/');
  if (!clean || clean.startsWith('/') || /^[A-Za-z]:/.test(clean)) return undefined;
  if (parts.some(part => part === '' || part === '.' || part === '..')) return undefined;
  return clean;
}

const SKILL_SCRIPT = /\.(sh|bash|zsh|py|js|mjs|cjs|ts|rb|ps1)$/;

/** Whether a path can hold agent configuration that the scanner reads. */
export function isCandidate(path: string): boolean {
  const parts = path.split('/');
  const name = parts.at(-1) ?? '';
  const parent = parts.at(-2);
  if (name === 'CLAUDE.md' || name === 'CLAUDE.local.md' || name === 'AGENTS.md') return true;
  if (name === '.mcp.json') return true;
  if (name === 'mcp.json' && (parent === '.vscode' || parent === '.cursor')) return true;
  if (parent === '.claude' && (name === 'settings.json' || name === 'settings.local.json')) return true;
  if (parent === '.codex' && name === 'config.toml') return true;
  if (parent === '.gemini' && name === 'settings.json') return true;
  if (parent === '.claude-plugin' && name === 'marketplace.json') return true;
  if (name === 'GEMINI.md') return true;
  const claude = parts.indexOf('.claude');
  if (claude >= 0) {
    const area = parts.at(claude + 1);
    if ((area === 'agents' || area === 'commands') && name.endsWith('.md')) return true;
    if (area === 'skills' && (name === 'SKILL.md' || SKILL_SCRIPT.test(name))) return true;
    if (area === 'hooks' && SKILL_SCRIPT.test(name)) return true;
  }
  if (parts.length === 3 && parts[0] === '.github' && parts[1] === 'workflows' && /\.ya?ml$/.test(name)) return true;
  if (
    name === 'CODEOWNERS' &&
    (parts.length === 1 || (parts.length === 2 && (parent === '.github' || parent === 'docs')))
  )
    return true;
  if (path === 'package.json' || path === '.agc.yaml') return true;
  // Agent Guard records: describe() output, inventory snapshots, host manifests.
  if (/^agent-guard[\w.-]*\.json$/.test(name) && parts.length <= 6) return true;
  return false;
}

/** Files in a directory on disk. Symbolic links are never followed. */
export class DirectorySource implements FileSource {
  readonly label: string;
  skipped = 0;
  readonly #root: string;
  #paths: string[] | undefined;

  constructor(root: string) {
    this.#root = root;
    this.label = root;
  }

  list(): readonly string[] {
    if (this.#paths) return this.#paths;
    const found: string[] = [];
    let entries = 0;
    const walk = (directory: string, depth: number): void => {
      if (depth > MAX_DEPTH || entries > MAX_ENTRIES) return;
      let names: string[];
      try {
        names = readdirSync(directory).sort();
      } catch {
        return;
      }
      for (const name of names) {
        entries += 1;
        if (entries > MAX_ENTRIES) {
          this.skipped += 1;
          return;
        }
        const full = join(directory, name);
        let info;
        try {
          info = lstatSync(full);
        } catch {
          continue;
        }
        if (info.isSymbolicLink()) continue;
        if (info.isDirectory()) {
          if (!SKIPPED_DIRECTORIES.has(name)) walk(full, depth + 1);
          continue;
        }
        if (!info.isFile()) continue;
        const path = relative(this.#root, full).split(sep).join('/');
        if (!isCandidate(path)) continue;
        if (info.size > MAX_FILE_BYTES) {
          this.skipped += 1;
          continue;
        }
        found.push(path);
      }
    };
    walk(this.#root, 0);
    this.#paths = found;
    return found;
  }

  read(path: string): string | undefined {
    if (!this.list().includes(path)) return undefined;
    try {
      return readFileSync(join(this.#root, ...path.split('/')), 'utf8');
    } catch {
      return undefined;
    }
  }

  readNamed(path: string): string | undefined {
    const clean = safeRelative(path);
    if (!clean) return undefined;
    let current = this.#root;
    try {
      for (const part of clean.split('/')) {
        current = join(current, part);
        const info = lstatSync(current);
        if (info.isSymbolicLink()) return undefined;
      }
      const info = lstatSync(current);
      if (!info.isFile() || info.size > MAX_FILE_BYTES) return undefined;
      return readFileSync(current, 'utf8');
    } catch {
      return undefined;
    }
  }
}

const SAFE_REF = /^[A-Za-z0-9][A-Za-z0-9._/@~^{}-]*$/;

/** Files at one commit, read with git. Nothing is checked out and nothing in the repo runs. */
export class GitSource implements FileSource {
  readonly label: string;
  skipped = 0;
  readonly #root: string;
  readonly #ref: string;
  #paths: string[] | undefined;

  constructor(root: string, ref: string) {
    if (!SAFE_REF.test(ref) || ref.includes('..')) throw new Error(`Refusing git ref: ${JSON.stringify(ref)}`);
    this.#root = root;
    this.#ref = ref;
    this.label = `${ref}`;
  }

  #git(args: string[], input?: string): Buffer {
    const result = spawnSync('git', ['-C', this.#root, ...args], {
      maxBuffer: 64 * 1024 * 1024,
      ...(input === undefined ? {} : { input }),
      env: { ...process.env, GIT_CONFIG_NOSYSTEM: '1', GIT_TERMINAL_PROMPT: '0' },
    });
    if (result.error) throw result.error;
    if (result.status !== 0) throw new Error(`git ${args[0]} failed: ${result.stderr.toString().trim()}`);
    return result.stdout;
  }

  list(): readonly string[] {
    if (this.#paths) return this.#paths;
    // No --long: sizes are read only for candidates, in one batch, so a partial (blobless)
    // clone does not fetch every blob in the tree.
    const out = this.#git(['ls-tree', '-r', '-z', this.#ref]).toString('utf8');
    const candidates: { path: string; object: string }[] = [];
    for (const record of out.split('\0')) {
      if (!record) continue;
      const tab = record.indexOf('\t');
      if (tab < 0) continue;
      const [mode, type, object] = record.slice(0, tab).trim().split(/\s+/);
      const path = record.slice(tab + 1);
      if (type !== 'blob' || mode === '120000' || !object || !isCandidate(path)) continue;
      const parts = path.split('/');
      if (parts.slice(0, -1).some(part => SKIPPED_DIRECTORIES.has(part))) continue;
      candidates.push({ path, object });
    }
    const sizes = candidates.length
      ? this.#git(['cat-file', '--batch-check=%(objectsize)'], candidates.map(item => item.object).join('\n') + '\n')
          .toString('utf8')
          .trim()
          .split('\n')
      : [];
    const found: string[] = [];
    candidates.forEach((item, index) => {
      if (Number(sizes[index]) > MAX_FILE_BYTES) this.skipped += 1;
      else found.push(item.path);
    });
    found.sort();
    this.#paths = found;
    return found;
  }

  read(path: string): string | undefined {
    if (!this.list().includes(path)) return undefined;
    try {
      // `./` makes the path relative to the scanned directory, matching ls-tree run from there.
      return this.#git(['show', `${this.#ref}:./${path}`]).toString('utf8');
    } catch {
      return undefined;
    }
  }

  readNamed(path: string): string | undefined {
    const clean = safeRelative(path);
    if (!clean) return undefined;
    try {
      const record = this.#git(['ls-tree', '-z', '--long', this.#ref, '--', `./${clean}`])
        .toString('utf8')
        .split('\0')[0];
      if (!record) return undefined;
      const [mode, type, , size] = record.slice(0, record.indexOf('\t')).trim().split(/\s+/);
      if (type !== 'blob' || mode === '120000' || Number(size) > MAX_FILE_BYTES) return undefined;
      return this.#git(['show', `${this.#ref}:./${clean}`]).toString('utf8');
    } catch {
      return undefined;
    }
  }
}

/** An in-memory source, for tests and for callers that already hold the files. */
export class MemorySource implements FileSource {
  readonly label: string;
  readonly skipped = 0;
  readonly #files: ReadonlyMap<string, string>;
  readonly #all: ReadonlyMap<string, string>;

  constructor(files: Readonly<Record<string, string>>, label = 'memory') {
    this.#all = new Map(Object.entries(files));
    this.#files = new Map(Object.entries(files).filter(([path]) => isCandidate(path)));
    this.label = label;
  }

  readNamed(path: string): string | undefined {
    const clean = safeRelative(path);
    const text = clean === undefined ? undefined : this.#all.get(clean);
    return text !== undefined && Buffer.byteLength(text) <= MAX_FILE_BYTES ? text : undefined;
  }

  list(): readonly string[] {
    return [...this.#files.keys()].sort();
  }

  read(path: string): string | undefined {
    return this.#files.get(path);
  }
}
