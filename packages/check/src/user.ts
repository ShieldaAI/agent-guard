import { closeSync, fstatSync, openSync, readFileSync, constants } from 'node:fs';
import { join } from 'node:path';
import type { TextFile } from './model.js';
import { MAX_FILE_BYTES } from './source.js';

/** The virtual folder managed (enterprise) settings are reported under. */
export const MANAGED_DIR = '<managed>';

/** Where Claude Code reads managed settings on each platform. */
export function managedSettingsPath(platform: NodeJS.Platform): string {
  if (platform === 'darwin') return '/Library/Application Support/ClaudeCode/managed-settings.json';
  if (platform === 'win32') return 'C:\\Program Files\\ClaudeCode\\managed-settings.json';
  return '/etc/claude-code/managed-settings.json';
}

/** Where Claude Code reads managed MCP servers: beside the managed settings. */
export function managedMcpPath(platform: NodeJS.Platform): string {
  return managedSettingsPath(platform).replace(/managed-settings\.json$/, 'managed-mcp.json');
}

/**
 * One regular file of at most 1 MiB. A link the user made in their own home is followed.
 * `missing` when there is no such file; `skipped` when it exists but cannot be used.
 */
function readSmall(path: string): { readonly text: string } | 'missing' | 'skipped' {
  let fd: number | undefined;
  try {
    fd = openSync(path, constants.O_RDONLY);
    const info = fstatSync(fd);
    if (!info.isFile() || info.size > MAX_FILE_BYTES) return 'skipped';
    return { text: readFileSync(fd, 'utf8') };
  } catch (error) {
    return (error as NodeJS.ErrnoException).code === 'ENOENT' ? 'missing' : 'skipped';
  } finally {
    if (fd !== undefined) closeSync(fd);
  }
}

/**
 * The agent settings outside the repository that apply to the person running the scan: Claude Code
 * user settings and user-scope MCP servers, Codex and Gemini CLI user config, and managed settings.
 * Paths are reported as `~/...` and `<managed>/managed-settings.json`. Only for local runs: in CI
 * these files belong to the runner, not to the people who use the agent.
 */
export function readUserConfig(
  home: string,
  platform: NodeJS.Platform = process.platform,
  onSkip: (path: string) => void = () => {},
): TextFile[] {
  const files: [string, string][] = [
    ['~/.claude/settings.json', join(home, '.claude', 'settings.json')],
    ['~/.claude.json', join(home, '.claude.json')],
    ['~/.codex/config.toml', join(home, '.codex', 'config.toml')],
    ['~/.gemini/settings.json', join(home, '.gemini', 'settings.json')],
    [`${MANAGED_DIR}/managed-settings.json`, managedSettingsPath(platform)],
    [`${MANAGED_DIR}/managed-mcp.json`, managedMcpPath(platform)],
  ];
  const out: TextFile[] = [];
  for (const [shown, real] of files) {
    const read = readSmall(real);
    if (read === 'skipped') onSkip(shown);
    else if (read !== 'missing') out.push({ path: shown, text: read.text });
  }
  return out;
}
