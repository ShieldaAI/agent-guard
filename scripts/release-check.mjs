import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
const root = fileURLToPath(new URL('../', import.meta.url));
const npmCli = process.env.npm_execpath;
if (!npmCli) throw new Error('Run publication through npm.');
const result = spawnSync(process.execPath, [npmCli, 'run', 'check'], { cwd: root, stdio: 'inherit' });
if (result.error || result.status !== 0) process.exit(result.status ?? 1);
