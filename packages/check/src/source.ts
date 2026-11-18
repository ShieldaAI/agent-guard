import { spawnSync } from 'node:child_process';
import { closeSync, constants, fstatSync, lstatSync, openSync, readdirSync, readFileSync, realpathSync } from 'node:fs';
import { isAbsolute, join, relative, sep } from 'node:path';

/** Files larger than this are skipped: agent config is small, and a huge file is not worth parsing. */
export const MAX_FILE_BYTES = 1_048_576;
/** The walk stops after visiting this many directory entries. */
export const MAX_ENTRIES = 200_000;
const MAX_DEPTH = 32;
export const SKIPPED_DIRECTORIES = new Set([
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
  /** Links where configuration lives that were not followed (they leave the root or do not resolve). */
  readonly linkedFiles?: readonly string[];
  /** Whether the walk stopped (MAX_ENTRIES, MAX_DEPTH), so some files were never looked at. */
  readonly truncated?: boolean;
  /** Paths that are configuration only on a case-insensitive file system (`.CLAUDE/settings.json`). */
  readonly caseVariants?: readonly string[];
  /** Pairs of paths that differ only in letter case, where one touches configuration. */
  readonly caseCollisions?: readonly (readonly [string, string])[];
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
 * The repository path a link in a git tree points to, when it can be resolved without following
 * other links: `target` is the link's text, resolved against the link's folder. Undefined for
 * absolute targets, ones that climb out of the root, and ones with `..` after a folder name (that
 * folder could itself be a link, and the operating system would resolve it before the `..`).
 */
export function linkTarget(linkPath: string, target: string): string | undefined {
  if (target.startsWith('/') || /^[A-Za-z]:/.test(target) || target.includes('\\')) return undefined;
  const out = linkPath.split('/').slice(0, -1);
  let named = false;
  for (const part of target.split('/')) {
    if (part === '' || part === '.') continue;
    if (part === '..') {
      if (named || !out.length) return undefined;
      out.pop();
    } else {
      named = true;
      out.push(part);
    }
  }
  return out.length ? out.join('/') : undefined;
}

/**
 * Whether a path is configuration once letter case is ignored, as on macOS and Windows, where
 * `.CLAUDE/settings.json` is the file Claude Code opens as `.claude/settings.json`.
 */
export function foldsToCandidate(path: string): boolean {
  const folded = foldPath(path);
  if (folded === path || !isCandidate(folded)) return false;
  // A lowercase `agents.md` in a docs folder is a page about agents: instruction names count only
  // at the root or inside an agent folder. Folder and settings names count anywhere.
  if (!/(^|\/)(CLAUDE(\.local)?|AGENTS|GEMINI|SKILL)\.md$/.test(folded)) return true;
  return !path.includes('/') || /^\.(claude|codex|gemini|cursor|github|kiro|opencode|windsurf)\/[^/]+$/i.test(path);
}

/** A path with letter case folded the way the agent would find it (`claude.md` → `CLAUDE.md`). */
export function foldPath(path: string): string {
  return path
    .toLowerCase()
    .replace(
      /(^|\/)claude(\.local)?\.md$/,
      (_, start: string, local: string | undefined) => `${start}CLAUDE${local ?? ''}.md`,
    )
    .replace(/(^|\/)(agents|gemini|skill)\.md$/, (_, start: string, name: string) => `${start}${name.toUpperCase()}.md`)
    .replace(/(^|\/)codeowners$/, '$1CODEOWNERS');
}

/** Instruction files: text an agent reads, as opposed to settings or agent definitions that grant tools. */
export function isInstructionPath(path: string): boolean {
  return /(^|\/)(CLAUDE(\.local)?|AGENTS|GEMINI|SKILL|copilot-instructions)\.md$|\.(instructions|prompt)\.md$|\.mdc$|(^|\/)\.(cursorrules|windsurfrules)$|(^|\/)(\.claude\/commands|\.kiro\/steering|\.windsurf\/rules|\.cursor\/rules)\//.test(
    path,
  );
}

/** Folders that hold agent configuration: a link there that cannot be followed is reported. */
const CONFIG_FOLDER =
  /(^|\/)(\.claude|\.codex|\.gemini|\.cursor|\.vscode|\.kiro|\.opencode|\.windsurf|\.github|\.claude-plugin|skills|hooks|agents|commands|workflows|rules|steering|settings)(\/|$)/;

/**
 * Removes instruction files reached through a link whose target the scan also reads at its own
 * path, so the same text is judged once. Settings and agent definitions stay: they apply where
 * the link sits.
 */
function dedupeLinked(found: string[], aliases: Map<string, string>): string[] {
  const direct = new Set(found.filter(path => !aliases.has(path)));
  return found.filter(path => {
    const target = aliases.get(path);
    if (target === undefined || !isInstructionPath(path) || !isInstructionPath(target) || !direct.has(target))
      return true;
    aliases.delete(path);
    return false;
  });
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

/**
 * Files in a directory on disk. A link is followed only as the operating system resolves it and
 * only inside the root; any other link where configuration lives is reported, never followed.
 */
export class DirectorySource implements FileSource {
  readonly label: string;
  skipped = 0;
  readonly skippedFiles: string[] = [];
  readonly linkedFiles: string[] = [];
  readonly caseVariants: string[] = [];
  readonly caseCollisions: [string, string][] = [];
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
    const root = (() => {
      try {
        return realpathSync.native(this.#root);
      } catch {
        return this.#root;
      }
    })();
    // `directory` is a real folder; `prefix` is the repository path it is seen at (a folder link
    // inside the root is walked at the link's own path, as the agent sees it).
    // Real folders on the current path: a folder link back to one of them is a loop, not more files.
    const open = new Set<string>();
    const walk = (directory: string, prefix: string, depth: number, linked = false): void => {
      if (entries > MAX_ENTRIES) return;
      let names: string[];
      try {
        names = readdirSync(directory).sort();
      } catch {
        return;
      }
      if (depth > MAX_DEPTH) {
        // Deeper folders are not looked at: say so rather than skip them silently.
        if (names.length) this.truncated = true;
        return;
      }
      let real: string;
      try {
        real = realpathSync.native(directory);
      } catch {
        real = directory;
      }
      if (open.has(real)) return;
      open.add(real);
      for (const name of names) {
        entries += 1;
        if (entries > MAX_ENTRIES) {
          this.skipped += 1;
          this.truncated = true;
          return;
        }
        const full = join(directory, name);
        const path = prefix ? `${prefix}/${name}` : name;
        let info;
        try {
          info = lstatSync(full);
        } catch {
          continue;
        }
        if (info.isSymbolicLink()) {
          // Resolved by the operating system itself, so `..` after a linked folder lands where the
          // agent would land. Inside the root it is read (a file) or walked (a folder) at the
          // link's path; anything else where configuration lives is reported, never followed.
          const target = this.#resolve(root, full);
          if (target?.kind === 'folder') {
            if (!SKIPPED_DIRECTORIES.has(name)) walk(target.real, path, depth + 1, true);
          } else if (target?.kind === 'file') {
            if (!isCandidate(path)) continue;
            if (target.size > MAX_FILE_BYTES) {
              this.skipped += 1;
              this.skippedFiles.push(path);
            } else {
              this.#aliases.set(path, target.path);
              found.push(path);
            }
          } else if (isCandidate(path) || CONFIG_FOLDER.test(path)) this.linkedFiles.push(path);
          continue;
        }
        if (info.isDirectory()) {
          if (!SKIPPED_DIRECTORIES.has(name)) walk(full, path, depth + 1, linked);
          continue;
        }
        if (info.isFile() && !isCandidate(path) && foldsToCandidate(path)) this.caseVariants.push(path);
        if (!info.isFile() || !isCandidate(path)) continue;
        if (info.size > MAX_FILE_BYTES) {
          this.skipped += 1;
          this.skippedFiles.push(path);
          continue;
        }
        // Inside a linked folder, the file is read at its real place.
        if (linked) this.#aliases.set(path, relative(root, full).split(sep).join('/'));
        found.push(path);
      }
      open.delete(real);
    };
    walk(this.#root, '', 0);
    // Assigned, not spread: a spread of a very large list overflows the call stack.
    const kept = dedupeLinked(found, this.#aliases);
    found.length = 0;
    for (const path of kept) found.push(path);
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

  /** A link's final target, as the operating system resolves it, when it is inside the root. */
  #resolve(
    root: string,
    full: string,
  ): { kind: 'file'; path: string; size: number } | { kind: 'folder'; real: string } | undefined {
    try {
      const real = realpathSync.native(full);
      const rel = relative(root, real);
      if (!rel || rel.startsWith('..') || isAbsolute(rel)) return undefined;
      const info = lstatSync(real);
      if (info.isDirectory()) return { kind: 'folder', real };
      if (!info.isFile()) return undefined;
      return { kind: 'file', path: rel.split(sep).join('/'), size: info.size };
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
  readonly caseVariants: string[] = [];
  readonly caseCollisions: [string, string][] = [];
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
      if (type !== 'blob' || !mode || !object) continue;
      tree.set(path, { mode, object });
      const parts = path.split('/');
      if (parts.slice(0, -1).some(part => SKIPPED_DIRECTORIES.has(part))) continue;
      if (mode === '120000') links.push({ path, object });
      else if (isCandidate(path)) candidates.push({ path, object });
    }
    // Links are read through their target when it is in the tree and reached without passing
    // through another link: a file at the link's path, or a folder walked at the link's path.
    if (links.length) {
      // Kept as bytes: sizes from git are byte counts, so decoding first would misalign targets.
      const batch = this.#git(['cat-file', '--batch'], links.map(link => link.object).join('\n') + '\n');
      const targets = new Map<string, string>();
      let offset = 0;
      for (const link of links) {
        const header = batch.indexOf(0x0a, offset);
        const size = Number(batch.subarray(offset, header).toString('utf8').split(' ')[2]);
        targets.set(link.path, batch.subarray(header + 1, header + 1 + size).toString('utf8'));
        offset = header + 1 + size + 1;
      }
      const passesLink = (path: string) => {
        const parts = path.split('/');
        for (let depth = 1; depth <= parts.length; depth += 1)
          if (tree.get(parts.slice(0, depth).join('/'))?.mode === '120000') return true;
        return false;
      };
      // Sorted paths, so the files below a folder are one range rather than a scan of the tree.
      const sorted = [...tree.keys()].sort();
      const below = (folder: string): string[] => {
        const start = `${folder}/`;
        let low = 0;
        let high = sorted.length;
        while (low < high) {
          const middle = (low + high) >> 1;
          if (sorted[middle]! < start) low = middle + 1;
          else high = middle;
        }
        const out: string[] = [];
        for (let index = low; index < sorted.length && sorted[index]!.startsWith(start); index += 1)
          out.push(sorted[index]!);
        return out;
      };
      /** A link's target file in the tree, when it resolves without passing through another link. */
      const fileOf = (linkPath: string): { path: string; object: string } | undefined => {
        const text = targets.get(linkPath);
        const resolved = text === undefined ? undefined : linkTarget(linkPath, text);
        if (resolved === undefined || passesLink(resolved)) return undefined;
        const entry = tree.get(resolved);
        return entry && entry.mode !== '120000' ? { path: resolved, object: entry.object } : undefined;
      };
      for (const link of links) {
        const text = targets.get(link.path)!;
        const resolved = linkTarget(link.path, text);
        const usable = resolved !== undefined && !passesLink(resolved);
        const file = fileOf(link.path);
        if (file) {
          if (isCandidate(link.path)) {
            this.#aliases.set(link.path, file.path);
            candidates.push({ path: link.path, object: file.object });
          }
          continue;
        }
        const inside = usable ? below(resolved!) : [];
        if (inside.length) {
          for (const path of inside) {
            const seen = `${link.path}${path.slice(resolved!.length)}`;
            const item = tree.get(path)!;
            // A link inside the linked folder: followed one step if it lands on a file in the tree.
            const nested = item.mode === '120000' ? fileOf(path) : { path, object: item.object };
            if (nested === undefined) {
              if (isCandidate(seen) || CONFIG_FOLDER.test(seen)) this.linkedFiles.push(seen);
              continue;
            }
            if (!isCandidate(seen)) continue;
            this.#aliases.set(seen, nested.path);
            candidates.push({ path: seen, object: nested.object });
          }
          continue;
        }
        if (isCandidate(link.path) || CONFIG_FOLDER.test(link.path)) this.linkedFiles.push(link.path);
      }
    }
    // Paths that differ only in letter case are one file on macOS and Windows: which one the agent
    // gets is up to the checkout, so a collision that touches configuration is reported.
    const byFold = new Map<string, string>();
    for (const path of tree.keys()) {
      const fold = path.toLowerCase();
      const other = byFold.get(fold);
      if (other !== undefined && (isCandidate(path) || isCandidate(other) || foldsToCandidate(path))) {
        this.caseCollisions.push([other, path]);
      } else byFold.set(fold, path);
    }
    for (const path of tree.keys())
      if (!isCandidate(path) && foldsToCandidate(path) && tree.get(path)!.mode !== '120000')
        this.caseVariants.push(path);
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
    const kept = dedupeLinked(found, this.#aliases).sort();
    this.#paths = kept;
    return kept;
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
