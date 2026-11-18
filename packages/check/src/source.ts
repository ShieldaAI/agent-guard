import { spawnSync } from 'node:child_process';
import { closeSync, constants, fstatSync, lstatSync, openSync, readdirSync, readFileSync, realpathSync } from 'node:fs';
import { isAbsolute, join, relative, sep } from 'node:path';

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
  /** Candidate files left out because they are larger than MAX_FILE_BYTES. */
  readonly skippedFiles?: readonly string[];
  /** Candidate files that are symbolic links: never followed, so never read. */
  readonly linkedFiles?: readonly string[];
  /** Whether the walk stopped at MAX_ENTRIES, so later files were never looked at. */
  readonly truncated?: boolean;
}

/** A repo-relative path with no `..`, no absolute prefix and no empty segment; undefined otherwise. */
export function safeRelative(path: string): string | undefined {
  const clean = path.replace(/\\/g, '/').replace(/^\.\//, '');
  const parts = clean.split('/');
  if (!clean || clean.startsWith('/') || /^[A-Za-z]:/.test(clean)) return undefined;
  if (parts.some(part => part === '' || part === '.' || part === '..')) return undefined;
  return clean;
}

/**
 * The repository path a link points to, when it stays inside the repository: `target` is the
 * link's text, resolved against the link's own folder. Undefined for absolute targets or ones
 * that climb out of the root.
 */
export function linkTarget(linkPath: string, target: string): string | undefined {
  if (target.startsWith('/') || /^[A-Za-z]:/.test(target) || target.includes('\\')) return undefined;
  const out = linkPath.split('/').slice(0, -1);
  for (const part of target.split('/')) {
    if (part === '' || part === '.') continue;
    if (part === '..') {
      if (!out.length) return undefined;
      out.pop();
    } else out.push(part);
  }
  return out.length ? out.join('/') : undefined;
}

const SKILL_SCRIPT = /\.(sh|bash|zsh|py|js|mjs|cjs|ts|rb|ps1)$/;

/** Files that can change where package runners fetch from. */
export const PACKAGE_SOURCE_FILES = new Set([
  '.npmrc',
  '.yarnrc',
  '.yarnrc.yml',
  'bunfig.toml',
  'uv.toml',
  'pip.conf',
  'pyproject.toml',
]);

/**
 * Which runners a package-source file redirects: `npm` (npx, pnpm, yarn, bun) for a registry,
 * scope registry or other config file in `.npmrc`, `.yarnrc(.yml)` or `bunfig.toml`; `python`
 * (uvx, pipx) for an index in `uv.toml`, `pip.conf` or a `pyproject.toml` uv index. Settings that
 * do not change where packages come from (`engine-strict`, hoisting) redirect nothing.
 */
export function packageSourceEcosystem(path: string, text: string): 'npm' | 'python' | undefined {
  const name = path.split('/').at(-1)!;
  if (!PACKAGE_SOURCE_FILES.has(name)) return undefined;
  if (name === '.npmrc' || name === '.yarnrc')
    return /^\s*((@[^:\s]+:)?registry|userconfig|globalconfig|globalignorefile|prefix)\s*[=\s]/m.test(text)
      ? 'npm'
      : undefined;
  if (name === '.yarnrc.yml') return /^\s*(npmRegistryServer|npmScopes|yarnPath)\s*:/m.test(text) ? 'npm' : undefined;
  if (name === 'bunfig.toml') return /\bregistry\b|scopes/.test(text) ? 'npm' : undefined;
  if (name === 'pyproject.toml') return /\[\[?tool\.uv\.index|index-url/.test(text) ? 'python' : undefined;
  return /index-url|index\b|find-links/.test(text) ? 'python' : undefined;
}

/** Whether a path can hold agent configuration that the scanner reads. */
export function isCandidate(path: string): boolean {
  const parts = path.split('/');
  // `~` and `<managed>` stand for settings outside the repository in reports; a repository folder
  // with that name is never read, so it cannot pose as someone's own or managed settings.
  if (parts[0] === '~' || parts[0] === '<managed>') return false;
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
  // OpenCode, the Cursor CLI, Copilot custom agents and instructions, Kiro, Windsurf and Cursor rules.
  if (name === 'opencode.json' || name === 'opencode.jsonc') return true;
  if (parts.at(-3) === '.opencode' && (parent === 'agent' || parent === 'agents') && name.endsWith('.md')) return true;
  if (parent === '.cursor' && name === 'cli.json') return true;
  if (parts.length >= 3 && parts.at(-3) === '.kiro' && parent === 'settings' && name === 'mcp.json') return true;
  if (parts.length >= 3 && parts.at(-3) === '.kiro' && parent === 'steering' && name.endsWith('.md')) return true;
  if (parts[0] === '.github' && parts.length === 3 && parent === 'agents' && name.endsWith('.md')) return true;
  if (parts[0] === '.github' && parts.length === 2 && name === 'copilot-instructions.md') return true;
  if (parts[0] === '.github' && parts.length === 3 && parent === 'instructions' && name.endsWith('.instructions.md'))
    return true;
  if (parts[0] === '.github' && parts.length === 3 && parent === 'prompts' && name.endsWith('.prompt.md')) return true;
  if (name === '.cursorrules' || name === '.windsurfrules') return true;
  if (parts.length >= 3 && parts.at(-3) === '.cursor' && parent === 'rules' && /\.mdc?$/.test(name)) return true;
  if (parts.length >= 3 && parts.at(-3) === '.windsurf' && parent === 'rules' && name.endsWith('.md')) return true;
  // Plugins: Claude Code plugin manifests and hooks, Agent Plugins (plugin.json beside mcp.json or
  // skills/), and skills anywhere.
  if (parent === '.claude-plugin' && name === 'plugin.json') return true;
  if (name === 'plugin.json' || name === 'mcp.json') return true;
  if (parent === 'hooks' && name === 'hooks.json') return true;
  if (name === 'SKILL.md' && parts.includes('skills')) return true;
  const claude = parts.indexOf('.claude');
  if (claude >= 0) {
    const area = parts.at(claude + 1);
    if ((area === 'agents' || area === 'commands') && name.endsWith('.md')) return true;
    if (area === 'skills' && (name === 'SKILL.md' || SKILL_SCRIPT.test(name))) return true;
    if (area === 'hooks' && SKILL_SCRIPT.test(name)) return true;
  }
  if (parts.length === 3 && parts[0] === '.github' && parts[1] === 'workflows' && /\.(ya?ml|md)$/.test(name))
    return true;
  if (
    name === 'CODEOWNERS' &&
    (parts.length === 1 || (parts.length === 2 && (parent === '.github' || parent === 'docs')))
  )
    return true;
  if (name === 'package.json' || path === '.agc.yaml') return true;
  if (PACKAGE_SOURCE_FILES.has(name)) return true;
  // Agent Guard records: describe() output, inventory snapshots, host manifests.
  if (/^agent-guard[\w.-]*\.json$/.test(name) && parts.length <= 6) return true;
  return false;
}

/** Files in a directory on disk. Symbolic links are never followed. */
export class DirectorySource implements FileSource {
  readonly label: string;
  skipped = 0;
  readonly skippedFiles: string[] = [];
  readonly linkedFiles: string[] = [];
  truncated = false;
  /** Candidate links that point to a regular file inside the root: read through their target. */
  readonly #aliases = new Map<string, string>();
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
          this.truncated = true;
          return;
        }
        const full = join(directory, name);
        let info;
        try {
          info = lstatSync(full);
        } catch {
          continue;
        }
        if (info.isSymbolicLink()) {
          // A link where configuration belongs is read through its target when that is a regular
          // file inside the root (as the agent itself would read it); otherwise it is reported.
          const linked = relative(this.#root, full).split(sep).join('/');
          if (!isCandidate(linked)) continue;
          const target = this.#insideTarget(full);
          // Instructions linked to a file the scan reads at its own path are judged there once.
          // A settings file is read through the link too: it applies where the link sits.
          if (target !== undefined && /\.mdc?$/.test(linked) && isCandidate(target.path)) continue;
          if (target === undefined) this.linkedFiles.push(linked);
          else if (target.size > MAX_FILE_BYTES) {
            this.skipped += 1;
            this.skippedFiles.push(linked);
          } else {
            this.#aliases.set(linked, target.path);
            found.push(linked);
          }
          continue;
        }
        if (info.isDirectory()) {
          if (!SKIPPED_DIRECTORIES.has(name)) walk(full, depth + 1);
          continue;
        }
        if (!info.isFile()) continue;
        const path = relative(this.#root, full).split(sep).join('/');
        if (!isCandidate(path)) continue;
        if (info.size > MAX_FILE_BYTES) {
          this.skipped += 1;
          this.skippedFiles.push(path);
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
    const alias = this.#aliases.get(path);
    if (alias !== undefined) return this.readNamed(alias);
    try {
      return readFileSync(join(this.#root, ...path.split('/')), 'utf8');
    } catch {
      return undefined;
    }
  }

  /** A link's final target, when it is a regular file inside the root, as a root-relative path. */
  #insideTarget(full: string): { path: string; size: number } | undefined {
    try {
      const root = realpathSync(this.#root);
      const real = realpathSync(full);
      const rel = relative(root, real);
      if (!rel || rel.startsWith('..') || isAbsolute(rel)) return undefined;
      const info = lstatSync(real);
      if (!info.isFile()) return undefined;
      return { path: rel.split(sep).join('/'), size: info.size };
    } catch {
      return undefined;
    }
  }

  readNamed(path: string): string | undefined {
    const clean = safeRelative(path);
    if (!clean) return undefined;
    const parts = clean.split('/');
    let current = this.#root;
    let fd: number | undefined;
    try {
      // Folders on the way must not be links; the file itself is opened without following a
      // link (O_NOFOLLOW), and its type and size are checked on the open descriptor, so a swap
      // between check and read cannot redirect it.
      for (const part of parts.slice(0, -1)) {
        current = join(current, part);
        if (lstatSync(current).isSymbolicLink()) return undefined;
      }
      const target = join(current, parts.at(-1)!);
      // Check the type before opening: opening a FIFO would block. O_NONBLOCK covers a swap after the check.
      if (!lstatSync(target).isFile()) return undefined;
      fd = openSync(target, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0) | (constants.O_NONBLOCK ?? 0));
      const info = fstatSync(fd);
      if (!info.isFile() || info.size > MAX_FILE_BYTES) return undefined;
      // Windows has no O_NOFOLLOW: confirm the opened file is the entry itself, not a link's target.
      const entry = lstatSync(target);
      if (entry.isSymbolicLink() || entry.ino !== info.ino || entry.dev !== info.dev) return undefined;
      return readFileSync(fd, 'utf8');
    } catch {
      return undefined;
    } finally {
      if (fd !== undefined) closeSync(fd);
    }
  }
}

const SAFE_REF = /^[A-Za-z0-9][A-Za-z0-9._/@~^{}-]*$/;

/** Files at one commit, read with git. Nothing is checked out and nothing in the repo runs. */
export class GitSource implements FileSource {
  readonly label: string;
  skipped = 0;
  readonly skippedFiles: string[] = [];
  readonly linkedFiles: string[] = [];
  /** Candidate links whose target is a regular file in the tree: read as that file. */
  readonly #aliases = new Map<string, string>();
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
    const tree = new Map<string, { mode: string; object: string }>();
    const links: { path: string; object: string }[] = [];
    for (const record of out.split('\0')) {
      if (!record) continue;
      const tab = record.indexOf('\t');
      if (tab < 0) continue;
      const [mode, type, object] = record.slice(0, tab).trim().split(/\s+/);
      const path = record.slice(tab + 1);
      if (type === 'blob' && mode && object) tree.set(path, { mode, object });
      if (type !== 'blob' || !object || !isCandidate(path)) continue;
      const parts = path.split('/');
      if (parts.slice(0, -1).some(part => SKIPPED_DIRECTORIES.has(part))) continue;
      if (mode === '120000') links.push({ path, object });
      else candidates.push({ path, object });
    }
    // A link is read through its target when the target is a regular file in the tree.
    if (links.length) {
      const texts = this.#git(['cat-file', '--batch'], links.map(link => link.object).join('\n') + '\n').toString(
        'utf8',
      );
      let offset = 0;
      for (const link of links) {
        const header = texts.indexOf('\n', offset);
        const size = Number(texts.slice(offset, header).split(' ')[2]);
        const target = texts.slice(header + 1, header + 1 + size);
        offset = header + 1 + size + 1;
        const resolved = linkTarget(link.path, target);
        const entry = resolved === undefined ? undefined : tree.get(resolved);
        if (entry && entry.mode !== '120000' && /\.mdc?$/.test(link.path) && isCandidate(resolved!)) continue;
        if (!entry || entry.mode === '120000') this.linkedFiles.push(link.path);
        else {
          this.#aliases.set(link.path, resolved!);
          candidates.push({ path: link.path, object: entry.object });
        }
      }
    }
    const sizes = candidates.length
      ? this.#git(['cat-file', '--batch-check=%(objectsize)'], candidates.map(item => item.object).join('\n') + '\n')
          .toString('utf8')
          .trim()
          .split('\n')
      : [];
    const found: string[] = [];
    candidates.forEach((item, index) => {
      if (Number(sizes[index]) > MAX_FILE_BYTES) {
        this.skipped += 1;
        this.skippedFiles.push(item.path);
      } else found.push(item.path);
    });
    found.sort();
    this.#paths = found;
    return found;
  }

  read(path: string): string | undefined {
    if (!this.list().includes(path)) return undefined;
    path = this.#aliases.get(path) ?? path;
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
  readonly skippedFiles: readonly string[];
  get skipped(): number {
    return this.skippedFiles.length;
  }
  readonly #files: ReadonlyMap<string, string>;
  readonly #all: ReadonlyMap<string, string>;

  constructor(files: Readonly<Record<string, string>>, label = 'memory') {
    this.#all = new Map(Object.entries(files));
    this.#files = new Map(
      Object.entries(files).filter(([path, text]) => isCandidate(path) && Buffer.byteLength(text) <= MAX_FILE_BYTES),
    );
    this.skippedFiles = Object.entries(files)
      .filter(([path, text]) => isCandidate(path) && Buffer.byteLength(text) > MAX_FILE_BYTES)
      .map(([path]) => path);
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
