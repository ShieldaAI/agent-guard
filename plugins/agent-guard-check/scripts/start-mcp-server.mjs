#!/usr/bin/env node
// Starts the read-only agent-guard-check MCP server (stdio) for the project the agent has open.
//
// What it runs: npx from the Node.js installation that runs this script, for the exact version
// below: `npx --yes --package=@shieldaai/agent-guard-check@<version> -- agent-guard-check-mcp <project>`.
// npx downloads the package from the npm registry in your own npm settings (registry.npmjs.org
// unless you changed it) the first time, then reuses its cache. The server itself only reads files
// under <project>, runs no repository code and makes no network calls.
//
// Why a launcher instead of calling npx directly: npx started inside the project would read the
// project's .npmrc (which can name another registry) and could run a copy of the scanner from
// the project's node_modules, so the repository under review would pick the tool reviewing it.
// This script starts npx from a folder outside the project, and drops npm_config_*, NODE_OPTIONS
// and NODE_PATH from npx's environment, which a project can set through its agent settings.

import { spawn } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, realpathSync, rmSync } from 'node:fs';
import { homedir, tmpdir } from 'node:os';
import { dirname, isAbsolute, join, parse, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

export const VERSION = '1.6.2';
export const PACKAGE = '@shieldaai/agent-guard-check';
const MIN_NODE_MAJOR = 22;

const pluginRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');

function real(path) {
  try {
    return realpathSync(path);
  } catch {
    return resolve(path);
  }
}

function isInside(child, parent) {
  const rel = relative(real(parent), real(child));
  return rel === '' || (!rel.startsWith('..') && !isAbsolute(rel));
}

/**
 * The project to check: an explicit argument, else the project directory the host names
 * (Claude Code sets CLAUDE_PROJECT_DIR), else the working directory the host started us in.
 * Returns undefined when the candidate cannot be the open project: the plugin itself, or a
 * filesystem root, the home folder or a folder above it (where a host that names no project
 * starts its servers). Scanning those would give a wrong answer, or read far outside the project.
 */
export function projectRoot({ argv = [], env = {}, cwd, plugin = pluginRoot, home = homedir() }) {
  const candidate = argv[0] ?? env.CLAUDE_PROJECT_DIR ?? cwd;
  if (!candidate) return undefined;
  const root = resolve(cwd ?? '.', candidate);
  if (isInside(root, plugin)) return undefined;
  if (real(root) === parse(real(root)).root) return undefined;
  if (home && isInside(home, root)) return undefined;
  return root;
}

/**
 * The environment for npx: the host's, without the variables that change which package npm
 * fetches or how Node runs it (npm_config_*, NODE_OPTIONS, NODE_PATH). A project can set those
 * through its agent settings; npm still reads your own ~/.npmrc, so a registry or proxy you set
 * there keeps working.
 */
export function npxEnv(env) {
  const out = {};
  for (const [key, value] of Object.entries(env)) {
    if (/^npm_config_/i.test(key) || /^NODE_(OPTIONS|PATH)$/i.test(key)) continue;
    out[key] = value;
  }
  return { ...out, npm_config_update_notifier: 'false', npm_config_fund: 'false', npm_config_audit: 'false' };
}

/**
 * npm's own npx-cli.js from the Node.js installation running this script, so neither PATH nor a
 * project-local shim decides what runs. Most POSIX installs link `npx` beside `node` to it
 * (Homebrew, nvm, Volta, the official tarballs); others keep npm in ../lib/node_modules/npm;
 * Windows installs keep it in node_modules beside node.exe.
 */
export function npxCli(execPath = process.execPath, { exists = existsSync, realpath = realpathSync } = {}) {
  const dir = dirname(execPath);
  const resolved = path => {
    try {
      return realpath(path);
    } catch {
      return undefined;
    }
  };
  const candidates = [
    resolved(join(dir, 'npx')),
    join(dir, '..', 'lib', 'node_modules', 'npm', 'bin', 'npx-cli.js'),
    join(dir, 'node_modules', 'npm', 'bin', 'npx-cli.js'),
  ];
  return candidates.find(
    candidate => candidate !== undefined && candidate.endsWith(join('npm', 'bin', 'npx-cli.js')) && exists(candidate),
  );
}

/**
 * A folder outside the project for npx to start in: the plugin's data folder, else a new private
 * temp folder (removed on exit).
 */
export function runnerDir(env = process.env) {
  const data = env.CLAUDE_PLUGIN_DATA ?? env.PLUGIN_DATA;
  if (data) {
    const dir = join(data, 'npx-runner');
    mkdirSync(dir, { recursive: true });
    return { dir, temporary: false };
  }
  return { dir: mkdtempSync(join(tmpdir(), 'agent-guard-check-')), temporary: true };
}

/** The npx command line: the MCP server bin of the pinned package, for one project. */
export function npxArgs(cli, root) {
  return [cli, '--yes', `--package=${PACKAGE}@${VERSION}`, '--', 'agent-guard-check-mcp', root];
}

function fail(message) {
  process.stderr.write(`agent-guard-check plugin: ${message}\n`);
  process.exit(1);
}

function main() {
  const major = Number(process.versions.node.split('.')[0]);
  if (major < MIN_NODE_MAJOR)
    fail(`Node.js ${MIN_NODE_MAJOR} or newer is required (this is ${process.versions.node}).`);
  const root = projectRoot({ argv: process.argv.slice(2), env: process.env, cwd: process.cwd() });
  if (!root)
    fail(
      'could not tell which project is open (the host named none, and the working folder is not a project). ' +
        'Start the server with the project path as its argument: ' +
        `node ${join(pluginRoot, 'scripts', 'start-mcp-server.mjs')} /path/to/project`,
    );
  const cli = npxCli();
  if (!cli) fail(`npm's npx was not found beside ${process.execPath}. Install Node.js with npm included.`);
  const runner = runnerDir();
  const cleanUp = () => {
    if (runner.temporary) rmSync(runner.dir, { recursive: true, force: true });
  };
  const child = spawn(process.execPath, npxArgs(cli, root), {
    cwd: runner.dir,
    stdio: 'inherit',
    env: npxEnv(process.env),
  });
  for (const signal of ['SIGINT', 'SIGTERM', 'SIGHUP']) process.on(signal, () => child.kill(signal));
  child.on('error', error => {
    cleanUp();
    fail(error.message);
  });
  child.on('exit', (code, signal) => {
    cleanUp();
    process.exit(code ?? (signal ? 1 : 0));
  });
}

function isEntry() {
  if (!process.argv[1]) return false;
  try {
    return realpathSync(process.argv[1]) === realpathSync(fileURLToPath(import.meta.url));
  } catch {
    return false;
  }
}

if (isEntry()) main();
