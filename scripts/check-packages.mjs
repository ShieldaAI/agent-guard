import { spawnSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, readFileSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('../', import.meta.url));
const npmCli = process.env.npm_execpath;
if (!npmCli) throw new Error('Run this script through npm run test:pack.');
const temp = mkdtempSync(join(tmpdir(), 'agent-guard-pack-'));
function run(command, args, cwd) {
  const result = spawnSync(command, args, { cwd, encoding: 'utf8' });
  if (result.error || result.status !== 0) throw new Error(result.stderr || result.stdout || result.error?.message || `${command} failed`);
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
  writeFileSync(join(consumer, 'consumer.mts'), readFileSync(new URL('package-consumer.mts', import.meta.url)));
  const readmes = [
    join(root, 'README.md'),
    ...['agent-guard', 'agent-guard-mcp', 'agent-guard-scenarios'].map(name =>
      join(consumer, 'node_modules', '@shieldaai', name, 'README.md')),
  ];
  for (const [index, path] of readmes.entries()) {
    const examples = [...readFileSync(path, 'utf8').matchAll(/```ts\r?\n([\s\S]*?)\r?\n```/g)];
    if (examples.length === 0) throw new Error(`Missing TypeScript README example: ${path}`);
    for (const [example, match] of examples.entries()) {
      writeFileSync(join(consumer, `readme-${index}-${example}.mts`), match[1]);
    }
  }
  writeFileSync(join(consumer, 'tsconfig.json'), JSON.stringify({
    compilerOptions: {
      target: 'ES2022', module: 'NodeNext', moduleResolution: 'NodeNext',
      strict: true, exactOptionalPropertyTypes: true, noUncheckedIndexedAccess: true,
      skipLibCheck: false, noEmitOnError: true, verbatimModuleSyntax: true,
      types: ['node'], typeRoots: [join(root, 'node_modules', '@types')],
      lib: ['ES2022'], outDir: 'compiled',
    },
    include: ['*.mts'],
  }));
  run(process.execPath, [join(root, 'node_modules', 'typescript', 'bin', 'tsc'), '--project', 'tsconfig.json'], consumer);
  console.log(run(process.execPath, ['compiled/consumer.mjs'], consumer).trim());
} finally {
  rmSync(temp, { recursive: true, force: true });
}
