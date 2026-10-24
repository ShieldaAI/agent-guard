import { spawnSync } from 'node:child_process';
import { rmSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { join } from 'node:path';

const root = fileURLToPath(new URL('../', import.meta.url));
const compiler = join(root, 'node_modules', 'typescript', 'bin', 'tsc');
const workspaces = ['packages/core', 'packages/mcp', 'packages/scenarios'];

// tsc leaves output from deleted source files behind. Remove it before packing.
for (const workspace of workspaces) {
  rmSync(join(root, workspace, 'dist'), { recursive: true, force: true });
}
for (const workspace of workspaces) {
  const result = spawnSync(process.execPath, [compiler, '-p', join(root, workspace, 'tsconfig.json')], {
    cwd: root,
    stdio: 'inherit',
  });
  if (result.error || result.status !== 0) process.exit(result.status ?? 1);
}
