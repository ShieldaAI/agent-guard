import { spawnSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('../', import.meta.url));
const npmCli = process.env.npm_execpath;
if (!npmCli) throw new Error('Run this script through npm run test:pack.');
const temp = mkdtempSync(join(tmpdir(), 'agent-guard-pack-'));
function run(command, args, cwd) {
  const result = spawnSync(command, args, { cwd, encoding: 'utf8' });
  if (result.error || result.status !== 0) throw new Error(result.stderr || result.error?.message || `${command} failed`);
  return result.stdout;
}
try {
  const tarballs = [];
  for (const workspace of ['packages/core', 'packages/mcp', 'packages/scenarios']) {
    const [pack] = JSON.parse(run(process.execPath, [npmCli, 'pack', '--json', '--ignore-scripts', '--workspace', workspace, '--pack-destination', temp], root));
    for (const { path } of pack.files) {
      if (!/^(dist\/.*\.(js|d\.ts)|package\.json|README\.md|LICENSE)$/.test(path)) {
        throw new Error(`Unexpected package file: ${path}`);
      }
    }
    for (const path of ['dist/index.js', 'dist/index.d.ts', 'README.md', 'LICENSE']) {
      if (!pack.files.some(file => file.path === path)) throw new Error(`Missing package file: ${path}`);
    }
    tarballs.push(join(temp, pack.filename));
  }
  const consumer = join(temp, 'consumer'); mkdirSync(consumer);
  writeFileSync(join(consumer, 'package.json'), JSON.stringify({ private: true, type: 'module' }));
  run(process.execPath, [npmCli, 'install', '--ignore-scripts', '--no-audit', '--no-fund', ...tarballs], consumer);
  const script = `
    import { AgentGuard } from '@shieldaai/agent-guard';
    import { registerMcpTool } from '@shieldaai/agent-guard-mcp';
    import { runConformance } from '@shieldaai/agent-guard-scenarios';
    if (typeof AgentGuard !== 'function' || typeof registerMcpTool !== 'function') throw new Error('Missing exports');
    const report = await runConformance();
    if (report.passed !== true) throw new Error(JSON.stringify(report));
    console.log('Packed packages imported successfully; all conformance scenarios passed.');
  `;
  console.log(run(process.execPath, ['--input-type=module', '-e', script], consumer).trim());
} finally {
  rmSync(temp, { recursive: true, force: true });
}
