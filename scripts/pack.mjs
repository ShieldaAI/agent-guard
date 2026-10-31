import { spawnSync } from 'node:child_process';
import { mkdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
const root = fileURLToPath(new URL('../', import.meta.url));
const npmCli = process.env.npm_execpath;
if (!npmCli) throw new Error('Run this script through npm run pack.');
mkdirSync(new URL('../artifacts/', import.meta.url), { recursive: true });
for (const workspace of ['packages/core', 'packages/mcp', 'packages/scenarios', 'packages/executor', 'packages/agent-map']) {
  const result = spawnSync(process.execPath, [npmCli, 'pack', '--ignore-scripts', '--workspace', workspace, '--pack-destination', 'artifacts'], { cwd: root, stdio: 'inherit' });
  if (result.error || result.status !== 0) process.exit(result.status ?? 1);
}
