import { spawnSync } from 'node:child_process';
import { cpSync, mkdtempSync, mkdirSync, readFileSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { trustedNpmCli } from './trusted-npm.mjs';

const root = fileURLToPath(new URL('../', import.meta.url));
const npmCli = trustedNpmCli();
const temp = mkdtempSync(join(tmpdir(), 'agent-guard-pack-'));
function run(command, args, cwd) {
  const result = spawnSync(command, args, { cwd, encoding: 'utf8' });
  if (result.error || result.status !== 0) throw new Error(result.stderr || result.stdout || result.error?.message || `${command} failed`);
  return result.stdout;
}
try {
  const tarballs = [];
  for (const workspace of ['packages/core', 'packages/mcp', 'packages/scenarios', 'packages/executor', 'packages/agent-map']) {
    mkdirSync(join(root, workspace, 'dist'), { recursive: true });
    writeFileSync(join(root, workspace, 'dist', 'obsolete-build-output.js'), 'throw new Error("Stale build output");\n');
    const [pack] = JSON.parse(run(process.execPath, [npmCli, 'pack', '--json', '--workspace', workspace, '--pack-destination', temp], root));
    if (pack.files.some(file => file.path === 'dist/obsolete-build-output.js')) {
      throw new Error(`Stale build output included in ${workspace}.`);
    }
    for (const { path } of pack.files) {
      if (!/^(dist\/.*\.(js|d\.ts)|package\.json|README\.md|LICENSE)$/.test(path)) {
        throw new Error(`Unexpected package file: ${path}`);
      }
    }
    for (const path of ['dist/index.js', 'dist/index.d.ts', 'README.md', 'LICENSE']) {
      if (!pack.files.some(file => file.path === path)) throw new Error(`Missing package file: ${path}`);
    }
    if (workspace === 'packages/executor' && !pack.files.some(file => file.path === 'dist/pilot-review-cli.js')) {
      throw new Error('Missing installed pilot review executable.');
    }
    if (workspace === 'packages/agent-map') {
      for (const path of ['dist/identity-cli.js', 'dist/identity-http.js', 'dist/oidc.js']) {
        if (!pack.files.some(file => file.path === path)) throw new Error(`Missing identity package file: ${path}`);
      }
    }
    if (workspace === 'packages/mcp') {
      const metadata = JSON.parse(readFileSync(join(root, workspace, 'package.json'), 'utf8'));
      if (!/^\d+\.\d+\.\d+$/.test(metadata.dependencies?.jose ?? '')) throw new Error('MCP JWT verification dependency must be directly pinned.');
    }
    tarballs.push(join(temp, pack.filename));
  }
  const consumer = join(temp, 'consumer'); mkdirSync(consumer);
  writeFileSync(join(consumer, 'package.json'), JSON.stringify({ private: true, type: 'module' }));
  run(process.execPath, [npmCli, 'install', '--ignore-scripts', '--no-audit', '--no-fund', ...tarballs], consumer);
  // A real previously published reader must reject new retirement semantics;
  // a mock schema checker cannot establish downgrade safety.
  run(process.execPath, [npmCli, 'install', '--ignore-scripts', '--no-audit', '--no-fund',
    'legacy-executor@npm:@shieldaai/agent-guard-executor@0.1.0-alpha.3'], consumer);
  cpSync(join(root, 'scripts/legacy-ledger-package-consumer.mjs'), join(consumer, 'legacy-ledger-consumer.mjs'));
  console.log(run(process.execPath, ['legacy-ledger-consumer.mjs'], consumer).trim());
  cpSync(join(root, 'scripts/recovery-package-consumer.mjs'), join(consumer, 'recovery-consumer.mjs'));
  console.log(run(process.execPath, ['recovery-consumer.mjs'], consumer).trim());
  writeFileSync(join(consumer, 'consumer.mts'), readFileSync(new URL('package-consumer.mts', import.meta.url)));
  cpSync(join(root, 'packages/executor/test/fixtures/packed-build-attestation.json'), join(consumer, 'packed-build-attestation.json'));
  cpSync(join(root, 'packages/executor/test/fixtures/pilot-review.mjs'), join(consumer, 'pilot-review-fixture.mjs'));
  cpSync(join(root, 'scripts/pilot-review-package-consumer.mjs'), join(consumer, 'pilot-review-consumer.mjs'));
  console.log(run(process.execPath, ['pilot-review-consumer.mjs'], consumer).trim());
  const readmes = [
    join(root, 'README.md'),
    ...['agent-guard', 'agent-guard-mcp', 'agent-guard-scenarios', 'agent-guard-executor', 'agent-map'].map(name =>
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
  writeFileSync(join(consumer, 'tool-permissions.mjs'), readFileSync(join(root, 'examples/tool-permissions.mjs')));
  console.log(run(process.execPath, ['tool-permissions.mjs'], consumer).trim());
  // These repository examples must work with the public, packed core API too.
  cpSync(join(root, 'examples/providers'), join(consumer, 'examples', 'providers'), { recursive: true });
  for (const example of ['openai-responses.mjs', 'anthropic-messages.mjs']) {
    const output = run(process.execPath, [join('examples', 'providers', example)], consumer).trim();
    const report = JSON.parse(output);
    if (report.provider !== example.split('-')[0] || report.mode !== 'offline-synthetic-replay' ||
        report.assertions !== 'passed' || report.approvedWrites !== 1 || report.forbiddenEffects !== 0 ||
        report.privateCanaryDisclosures !== 0) {
      throw new Error(`Installed protected ticket workflow failed: ${example}`);
    }
    console.log(output);
  }
  cpSync(join(root, 'evals/provider-tools'), join(consumer, 'evals/provider-tools'), { recursive: true });
  mkdirSync(join(consumer, 'scripts'));
  for (const name of ['evaluate-provider-tools.mjs', 'evaluate-provider-trials.mjs', 'provider-trials-package-consumer.mjs']) {
    cpSync(join(root, 'scripts', name), join(consumer, 'scripts', name));
  }
  console.log(run(process.execPath, ['scripts/provider-trials-package-consumer.mjs'], consumer).trim());
  writeFileSync(join(consumer, 'identity-consumer.mjs'), readFileSync(new URL('identity-package-consumer.mjs', import.meta.url)));
  writeFileSync(join(consumer, 'oidc-provider.mjs'), readFileSync(join(root, 'packages/agent-map/test/helpers/oidc-provider.mjs')));
  console.log(run(process.execPath, ['--test', 'identity-consumer.mjs'], consumer).trim());
  writeFileSync(join(consumer, 'mcp-credentials-consumer.mjs'), readFileSync(new URL('mcp-credential-package-consumer.mjs', import.meta.url)));
  console.log(run(process.execPath, ['--test', 'mcp-credentials-consumer.mjs'], consumer).trim());
  for (const name of ['agent-guard-map', 'agent-guard-map-identity', 'agent-guard-ledger']) {
    const help = process.platform === 'win32'
      ? run('cmd.exe', ['/d', '/c', `node_modules\\.bin\\${name}.cmd`, '--help'], consumer)
      : run(join(consumer, 'node_modules', '.bin', name), ['--help'], consumer);
    const prefix = name === 'agent-guard-ledger' ? `${name} keygen --keyring ` : `${name} --config `;
    if (!help.startsWith(prefix)) throw new Error(`Installed ${name} launcher did not print its usage.`);
  }
} finally {
  rmSync(temp, { recursive: true, force: true });
}
