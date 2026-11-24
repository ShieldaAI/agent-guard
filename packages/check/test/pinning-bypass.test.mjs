// AGC-SUP-006 (a pinned MCP server that can still change) and the AGC-GOV-004 bypass check:
// edge cases, other agent formats, diff mode, the CLI end to end, and every branch of the
// GitHub bypass reading. Response shapes follow real GitHub API answers recorded on 2026-11-24.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { existsSync, mkdtempSync, mkdirSync, readFileSync, writeFileSync, rmSync } from 'node:fs';
import { createRequire } from 'node:module';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { diffScans, fetchBranchRules, runCli } from '@shieldaai/agent-guard-check';
import { FLAG_TABLES, npxArgv } from '../dist/runner-flags.js';
import { lockfileVersions } from '../dist/model.js';
import { findingsFor, json, mcp, scanFiles, settings } from './helpers.mjs';

const DIGEST = `sha256:${'0a'.repeat(32)}`;
const sup = (files, options) => {
  const result = scanFiles(files, options);
  return { six: findingsFor(result, 'AGC-SUP-006'), one: findingsFor(result, 'AGC-SUP-001') };
};
const server = (command, args) => ({ '.mcp.json': mcp({ s: { command, args } }) });

// ---------------------------------------------------------------- AGC-SUP-006

test('AGC-SUP-006: every launcher form, and never together with AGC-SUP-001', () => {
  // [label, command, args, expected: '006' | '001' | 'none', fix fragment]
  const cases = [
    ['npx -y exact', 'npx', ['-y', 'pkg@1.2.3'], '006', 'npx --no-install pkg'],
    ['npx without -y', 'npx', ['pkg@1.2.3'], '006'],
    ['npx --yes scoped', 'npx', ['--yes', '@acme/mcp@1.2.3'], '006', 'npx --no-install @acme/mcp"'],
    ['npx prerelease', 'npx', ['-y', 'pkg@1.2.3-beta.1'], '006'],
    ['npx v-prefixed', 'npx', ['-y', 'pkg@v1.2.3'], '006'],
    ['npx caret range', 'npx', ['-y', 'pkg@^1.2.3'], '001'],
    ['npx major only', 'npx', ['-y', 'pkg@1'], '001'],
    ['npx latest', 'npx', ['-y', 'pkg@latest'], '001'],
    ['npx bare', 'npx', ['-y', 'pkg'], '001'],
    ['npx --no-install', 'npx', ['--no-install', 'pkg'], 'none'],
    ['npx --no', 'npx', ['--no', 'pkg@1.2.3'], 'none'],
    ['npx --offline (cache, not lockfile)', 'npx', ['--offline', 'pkg@1.2.3'], '006'],
    ['npx local path', 'npx', ['-y', './tools/mcp'], 'none'],
    ['npx file:', 'npx', ['-y', 'file:../mcp'], 'none'],
    ['npm exec', 'npm', ['exec', '--yes', '--', 'pkg@1.2.3'], '006', 'npx --no-install pkg'],
    ['pnpm dlx', 'pnpm', ['dlx', 'pkg@1.2.3'], '006', 'pnpm exec pkg'],
    ['pnpx', 'pnpx', ['pkg@1.2.3'], '006', 'pnpm exec pkg'],
    ['yarn dlx', 'yarn', ['dlx', 'pkg@1.2.3'], '006', 'yarn run pkg'],
    ['bunx', 'bunx', ['pkg@1.2.3'], '006', 'bun run pkg'],
    ['Windows npx.cmd', 'C:\\Program Files\\nodejs\\npx.cmd', ['-y', 'pkg@1.2.3'], '006'],
    ['cmd /c', 'cmd', ['/c', 'npx', '-y', 'pkg@1.2.3'], '006'],
    ['sh -c', 'sh', ['-c', 'npx -y pkg@1.2.3'], '006'],
    ['sh -c two commands', 'sh', ['-c', 'npx -y pkg@1.2.3 && curl x'], '001'],
    ['uvx exact', 'uvx', ['mcp-server-fetch==2026.11.18'], '006', 'locked environment'],
    ['uvx ===', 'uvx', ['pkg===1.2.3'], '006'],
    ['uvx --from', 'uvx', ['--from', 'pkg==1.2.3', 'pkg-cmd'], '006'],
    ['pipx run', 'pipx', ['run', 'pkg==1.2.3'], '006', 'locked environment'],
    ['uvx range', 'uvx', ['pkg>=1.0'], '001'],
    ['uvx wildcard', 'uvx', ['pkg==1.*'], '001'],
    ['uvx bare', 'uvx', ['pkg'], '001'],
    ['docker tag', 'docker', ['run', '-i', '--rm', 'ghcr.io/o/mcp:1.4.2'], '006', 'ghcr.io/o/mcp@sha256:<digest>'],
    ['podman tag', 'podman', ['run', '-i', 'o/mcp:1.4.2'], '006'],
    ['docker valued flags', 'docker', ['run', '-e', 'A=1', '--name', 'n', '-v', '/a:/b', 'o/mcp:2'], '006'],
    ['registry port, tag', 'docker', ['run', '-i', 'localhost:5000/mcp:1.0'], '006', 'localhost:5000/mcp@sha256'],
    ['registry port, no tag', 'docker', ['run', '-i', 'localhost:5000/mcp'], '001'],
    ['docker no tag', 'docker', ['run', '-i', 'o/mcp'], '001'],
    ['docker latest', 'docker', ['run', '-i', 'o/mcp:latest'], '001'],
    ['docker digest', 'docker', ['run', '-i', `o/mcp@${DIGEST}`], 'none'],
    ['docker tag and digest', 'docker', ['run', '-i', `o/mcp:1.4.2@${DIGEST}`], 'none'],
    ['docker entrypoint', 'docker', ['run', '--entrypoint', 'sh', 'o/mcp:1.4.2'], 'none'],
    ['not a runner', 'node', ['server.js'], 'none'],
  ];
  for (const [label, command, args, expected, fix] of cases) {
    const { six, one } = sup(server(command, args));
    assert.equal(six.length, expected === '006' ? 1 : 0, `${label}: AGC-SUP-006`);
    assert.equal(one.length, expected === '001' ? 1 : 0, `${label}: AGC-SUP-001`);
    if (six[0]) {
      assert.equal(six[0].severity, 'low', label);
      assert.equal(six[0].location.file, '.mcp.json', label);
      if (fix) assert.ok(six[0].fix.includes(fix), `${label}: fix "${six[0].fix}" lacks "${fix}"`);
    }
  }
});

test('AGC-SUP-006: the message says what can change, and admits the exception', () => {
  const [npm] = sup(server('npx', ['-y', 'pkg@1.2.3'])).six;
  assert.match(npm.message, /^MCP server "s" pins "pkg@1.2.3", but npx resolves its dependencies again/);
  assert.match(npm.message, /unless the package fixes every dependency version/);
  const [image] = sup(server('docker', ['run', '-i', 'o/mcp:1.4.2'])).six;
  assert.match(image.message, /runs image "o\/mcp:1.4.2" by tag/);
});

test('AGC-SUP-006: a package the repository installs is left alone, from either dependency list', () => {
  const launch = server('npx', ['-y', 'pkg@1.2.3']);
  for (const key of ['dependencies', 'devDependencies'])
    assert.equal(sup({ ...launch, 'package.json': json({ name: 'app', [key]: { pkg: '1.2.3' } }) }).six.length, 0, key);
  // Another package's dependency does not make this one installed.
  assert.equal(sup({ ...launch, 'package.json': json({ devDependencies: { other: '1.0.0' } }) }).six.length, 1);
});

test('AGC-SUP-001/006: dlx runners fetch even when the repository has the package installed', () => {
  const dep = { 'package.json': json({ devDependencies: { pkg: '1.2.3' } }) };
  const cases = [
    // [command, args, rule expected with pkg in devDependencies]
    ['npx', ['-y', 'pkg@1.2.3'], 'none'],
    ['npm', ['exec', '--yes', '--', 'pkg@1.2.3'], 'none'],
    // bunx uses the project's copy only for a bare name (bun's bunx_command.rs).
    ['bunx', ['pkg@1.2.3'], '006'],
    ['bunx', ['pkg'], 'none'],
    ['npx', ['-y', 'pkg'], 'none'],
    ['pnpm', ['dlx', 'pkg@1.2.3'], '006'],
    ['yarn', ['dlx', 'pkg@1.2.3'], '006'],
    ['pnpx', ['pkg@1.2.3'], '006'],
    ['pnpm', ['dlx', 'pkg'], '001'],
    ['yarn', ['dlx', 'pkg'], '001'],
  ];
  for (const [command, args, expected] of cases) {
    const { six, one } = sup({ ...server(command, args), ...dep });
    const label = `${command} ${args.join(' ')}`;
    assert.equal(six.length, expected === '006' ? 1 : 0, `${label}: AGC-SUP-006`);
    assert.equal(one.length, expected === '001' ? 1 : 0, `${label}: AGC-SUP-001`);
  }
});

test('AGC-SUP-001/006: a value of a docker run flag is never read as the image', () => {
  const image = 'ghcr.io/github/github-mcp-server';
  const flags = [
    ['-u', '1000:1000'],
    ['--user', 'app:app'],
    ['--add-host', 'host.docker.internal:host-gateway'],
    ['--platform', 'linux/amd64'],
    ['--security-opt', 'label=disable'],
    ['--mount', 'type=bind,src=/a,dst=/b'],
    ['--cap-drop', 'ALL'],
    ['--env-file', '.env'],
    ['--network', 'host'],
    ['-w', '/work'],
    ['--log-opt', 'max-size=10m'],
    ['--ulimit', 'nofile=1024:1024'],
    ['--gpus', 'device=7'],
    ['--cpu-count', '2'],
    ['--ip6', '::1'],
  ];
  for (const [flag, value] of flags) {
    const run = tail => sup(server('docker', ['run', '-i', '--rm', flag, value, ...tail]));
    const digest = run([`${image}@${DIGEST}`, 'stdio']);
    assert.deepEqual([digest.six.length, digest.one.length], [0, 0], `${flag} ${value}, digest`);
    const tagged = run([`${image}:v0.20.1`]);
    assert.equal(tagged.six.length, 1, `${flag} ${value}, tag`);
    assert.match(tagged.six[0].message, new RegExp(`image "${image}:v0.20.1" by tag`), flag);
    const bare = run([image]);
    assert.equal(bare.one.length, 1, `${flag} ${value}, no tag`);
    assert.match(bare.one[0].message, new RegExp(`image "${image}" with no fixed tag`), flag);
  }
  // `--flag=value` is one word whatever the flag.
  assert.equal(sup(server('docker', ['run', '--user=1000:1000', `${image}@${DIGEST}`])).six.length, 0);
});

test('AGC-SUP-006: each extra package is judged on its own', () => {
  const { six, one } = sup(server('npx', ['-y', '-p', 'helper@2.0.0', '-p', 'floating', 'pkg@1.2.3']));
  assert.deepEqual(six.map(f => f.message.match(/pins "([^"]+)"/)[1]).sort(), ['helper@2.0.0']);
  assert.equal(one.length, 1, 'floating is unpinned');
  const uv = sup(server('uvx', ['--with', 'extra==1.0', 'pkg==1.2.3']));
  assert.equal(uv.six.length, 2);
  assert.equal(new Set(uv.six.map(f => f.fingerprint)).size, 2, 'distinct fingerprints');
});

test('runner flags: values are skipped, the package is found, and the server’s own arguments are left alone', () => {
  // Each pair: launch, then [rule, package] for every AGC-SUP-001/006 finding. Before 1.7.0, flags that
  // take a value (`--python 3.12`, `--registry URL`) were read as the package, `--with x` hid the
  // real package, and `--offline` among the server's arguments switched the check off.
  const named = (command, args) =>
    scanFiles(server(command, args))
      .findings.filter(f => f.ruleId === 'AGC-SUP-001' || f.ruleId === 'AGC-SUP-006')
      .map(f => `${f.ruleId.slice(-3)} ${f.message.match(/(?:starts|pins) "([^"]+)"/)[1]}`)
      .sort();
  const cases = [
    [
      ['uvx', ['--with', 'extra==1.0', 'floating']],
      ['001 floating', '006 extra==1.0'],
    ],
    [
      ['uvx', ['--with=extra==1.0', 'pkg==1.2.3']],
      ['006 extra==1.0', '006 pkg==1.2.3'],
    ],
    [['uvx', ['--python', '3.12', 'floating']], ['001 floating']],
    [['uvx', ['-p', '3.12', 'pkg==1.2.3']], ['006 pkg==1.2.3']],
    [['uvx', ['--python=3.12', 'pkg==1.2.3']], ['006 pkg==1.2.3']],
    [['uvx', ['--index-url', 'https://i.example/simple', 'floating']], ['001 floating']],
    [['uvx', ['--from', 'pkg==1.2.3', 'cmd', '--with', 'x']], ['006 pkg==1.2.3']],
    [['pipx', ['run', '--spec', 'pkg==1.2.3', 'cmd']], ['006 pkg==1.2.3']],
    [['pipx', ['run', '--python', '3.12', 'floating']], ['001 floating']],
    [['npx', ['--registry', 'https://r.example', 'floating']], ['001 floating']],
    [['npx', ['-y', 'pkg@1.2.3', '--offline']], ['006 pkg@1.2.3']],
    [['npx', ['-y', 'pkg@1.2.3', '--package', 'x']], ['006 pkg@1.2.3']],
    [['npx', ['-y', '--package=a@1.0.0', 'cmd']], ['006 a@1.0.0']],
    [['npx', ['-y', '--', 'pkg@1.2.3']], ['006 pkg@1.2.3']],
    [['pnpm', ['dlx', '-c', 'pkg@1.2.3']], ['006 pkg@1.2.3']],
    [['pnpm', ['dlx', '--package', 'a@1.0.0', 'cmd']], ['006 a@1.0.0']],
    [['bunx', ['--bun', 'pkg@1.2.3']], ['006 pkg@1.2.3']],
    // Cases from public .mcp.json files, 2026-11-24.
    [
      [
        'uvx',
        ['--python', '>=3.10', '--python-preference', 'only-system', '--with', 'mcp<2', 'mcp-server-tree-sitter'],
      ],
      ['001 mcp-server-tree-sitter', '001 mcp<2'],
    ],
    [['uvx', ['--env-file', '/repo/.env', 'zscaler-mcp@0.15.4']], ['006 zscaler-mcp@0.15.4']],
    [['bunx', ['mintlify-mcp', '-p', '6648a29700dd75f3275ec70a']], ['001 mintlify-mcp']],
    [['npx', ['-y', '@mizchi/lsmcp', '-p', 'tsgo']], ['001 @mizchi/lsmcp']],
    [['pipx', ['run', '--python', '/usr/local/bin/python3.12', 'analytics-mcp']], ['001 analytics-mcp']],
    // uv's own forms: `pkg@version`, `-w` for --with, git sources pinned by full commit only.
    [['uvx', ['pkg@2025.1.17']], ['006 pkg@2025.1.17']],
    [['uvx', ['pkg@1.0rc1']], ['006 pkg@1.0rc1']],
    [['uvx', ['pkg@latest']], ['001 pkg@latest']],
    [['uvx', ['pkg@1abc']], ['001 pkg@1abc']],
    [
      ['uvx', ['-w', 'extra==1.0', 'pkg==1.2.3']],
      ['006 extra==1.0', '006 pkg==1.2.3'],
    ],
    [
      ['uvx', ['--from', `git+https://github.com/o/r.git@a${'1'.repeat(39)}`, 'cmd']],
      [`006 git+https://github.com/o/r.git@a${'1'.repeat(39)}`],
    ],
    [['uvx', ['--from', 'git+https://github.com/o/r.git@main', 'cmd']], ['001 git+https://github.com/o/r.git@main']],
    [
      ['uvx', ['--from', 'git+https://github.com/o/r.git@v1.2.0', 'cmd']],
      ['001 git+https://github.com/o/r.git@v1.2.0'],
    ],
    [['uvx', ['--exclude-newer-package', 'x=2025-01-01', '--torch-backend', 'cpu', 'pkg==1.2.3']], ['006 pkg==1.2.3']],
    // npm options that take a value, read from npm's own definitions.
    [
      ['npx', ['--cache', '/tmp/c', '--before', '2025-01-01', '--userconfig', '/x/.npmrc', '-y', 'pkg@1.2.3']],
      ['006 pkg@1.2.3'],
    ],
    [['npx', ['-C', '/srv', '-w', 'api', 'pkg']], ['001 pkg']],
    [['pnpm', ['dlx', '--allow-build', 'esbuild', 'pkg@1.2.3']], ['006 pkg@1.2.3']],
    [['npx', ['-y']], []],
    [['uvx', ['--python']], []],
  ];
  for (const [[command, args], expected] of cases)
    assert.deepEqual(named(command, args), expected, `${command} ${args.join(' ')}`);
});

test('AGC-SUP-006: servers in other agents’ files and in workflows', () => {
  const pinned = { command: 'npx', args: ['-y', 'pkg@1.2.3'] };
  const files = {
    '.cursor/mcp.json': mcp({ c: pinned }),
    '.vscode/mcp.json': json({ servers: { v: pinned } }),
    '.codex/config.toml': '[mcp_servers.x]\ncommand = "npx"\nargs = ["-y", "pkg@1.2.3"]\n',
    '.gemini/settings.json': mcp({ g: pinned }),
  };
  for (const [path, text] of Object.entries(files)) {
    const { six } = sup({ [path]: text });
    assert.equal(six.length, 1, path);
    assert.equal(six[0].location.file, path);
  }
});

test('AGC-SUP-006: a version bump is not new under --base; a moved image tag is', () => {
  const at = (command, args) => scanFiles(server(command, args));
  const bump = diffScans(at('npx', ['-y', 'pkg@1.2.3']), at('npx', ['-y', 'pkg@1.2.4']));
  assert.ok(!bump.added.some(f => f.ruleId === 'AGC-SUP-006'), 'same server, newer pin: old debt');
  const same = diffScans(at('docker', ['run', '-i', 'o/m:1']), at('docker', ['run', '-i', 'o/m:1']));
  assert.ok(!same.added.some(f => f.ruleId === 'AGC-SUP-006'));
  const moved = diffScans(at('docker', ['run', '-i', 'o/m:1']), at('docker', ['run', '-i', 'o/m:2']));
  assert.ok(
    moved.added.some(f => f.ruleId === 'AGC-SUP-006'),
    'a new image is judged again, as in AGC-SUP-001',
  );
  const fixed = diffScans(at('docker', ['run', '-i', 'o/m:1']), at('docker', ['run', '-i', `o/m@${DIGEST}`]));
  assert.ok(
    fixed.resolved.some(f => f.ruleId === 'AGC-SUP-006'),
    'pinning the digest resolves it',
  );
});

test('AGC-SUP-006 through the CLI: low, so it does not fail a default run; suppressible with a reason', async t => {
  const dir = mkdtempSync(join(tmpdir(), 'agc-sup6-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  writeFileSync(join(dir, '.mcp.json'), mcp({ s: { command: 'npx', args: ['-y', 'pkg@1.2.3'] } }));
  const run = async (...args) => {
    let stdout = '';
    const code = await runCli([dir, ...args], { stdout: s => (stdout += s), stderr: () => {}, cwd: dir, env: {} });
    return { code, stdout };
  };
  const plain = await run('--format', 'json');
  assert.equal(plain.code, 0, 'default fail_on is high');
  assert.ok(JSON.parse(plain.stdout).findings.some(f => f.ruleId === 'AGC-SUP-006'));
  assert.equal((await run('--fail-on', 'low')).code, 1);
  const sarif = JSON.parse((await run('--format', 'sarif')).stdout);
  assert.ok(sarif.runs[0].tool.driver.rules.some(rule => rule.id === 'AGC-SUP-006'));
  assert.ok(sarif.runs[0].results.some(result => result.ruleId === 'AGC-SUP-006'));
  writeFileSync(
    join(dir, '.agc.yaml'),
    'ignore:\n  - rule: AGC-SUP-006\n    reason: the package bundles its dependencies\n',
  );
  const quiet = JSON.parse((await run('--format', 'json')).stdout);
  assert.ok(!quiet.findings.some(f => f.ruleId === 'AGC-SUP-006'));
  assert.equal(
    quiet.suppressed.find(s => s.finding.ruleId === 'AGC-SUP-006').reason,
    'the package bundles its dependencies',
  );
});

// ---------------------------------------------------------------- bypass: fetchBranchRules

const API = 'https://api.github.com';
function fakeGitHub(routes, api = API) {
  const requests = [];
  const fetch = async (url, init) => {
    requests.push({ url: String(url), headers: init?.headers ?? {} });
    const path = String(url).slice(api.length).replace(/\?.*$/, '');
    const route = routes[path];
    if (typeof route === 'function') return route();
    const [status, body, headers = {}] = route ?? [404, { message: 'Not Found' }];
    return new Response(JSON.stringify(body), { status, headers });
  };
  return { fetch, requests };
}
// The shape GitHub returns for a pull_request rule (recorded from a real repository).
const ownerRule = (id, required = true) => ({
  type: 'pull_request',
  parameters: {
    required_approving_review_count: 1,
    dismiss_stale_reviews_on_push: true,
    required_reviewers: [],
    require_code_owner_review: required,
    require_last_push_approval: false,
    required_review_thread_resolution: false,
    allowed_merge_methods: ['merge', 'squash', 'rebase'],
  },
  ruleset_source_type: 'Repository',
  ruleset_source: 'acme/app',
  ruleset_id: id,
});
// Recorded: the admin-token view of a ruleset with the admin role on its bypass list.
const adminBypass = { actor_id: 5, actor_type: 'RepositoryRole', bypass_mode: 'always' };
const ruleset = (id, actors) => [
  200,
  { id, name: 'r', target: 'branch', enforcement: 'active', ...(actors ? { bypass_actors: actors } : {}) },
];
const rulesOn = (rules, extra = {}) => ({ '/repos/acme/app/rules/branches/main': [200, rules], ...extra });
const read = (routes, more = {}) =>
  fetchBranchRules({ repo: 'acme/app', branch: 'main', token: 'tok', fetch: fakeGitHub(routes).fetch, ...more });

test('bypass: one ruleset names each kind of actor, once each, in plain words', async () => {
  const actors = [
    adminBypass,
    { actor_id: 4, actor_type: 'RepositoryRole', bypass_mode: 'always' },
    { actor_id: 1, actor_type: 'OrganizationAdmin', bypass_mode: 'always' },
    { actor_id: 9, actor_type: 'Team', bypass_mode: 'pull_request' },
    { actor_id: 8, actor_type: 'Team', bypass_mode: 'pull_request' },
    { actor_id: 3, actor_type: 'Integration', bypass_mode: 'exempt' },
    { actor_id: 2, actor_type: 'DeployKey', bypass_mode: 'always' },
    { actor_id: 1, actor_type: 'EnterpriseOwner', bypass_mode: 'always' },
    { actor_id: 1, actor_type: 'SomethingNew', bypass_mode: 'always' },
    'not an object',
  ];
  const rules = await read(
    rulesOn([ownerRule(7)], {
      '/repos/acme/app/rulesets/7': ruleset(7, actors),
      '/repos/acme/app/branches/main': [200, { protection: { enabled: false } }],
    }),
  );
  assert.equal(rules.codeOwnerBypass, 'possible');
  assert.equal(
    rules.bypassWhy,
    'repository admins, a repository role, organization admins, a team, a GitHub App, deploy keys, enterprise owners and someone may bypass every ruleset that requires it',
  );
});

test('bypass: every rule applies, so only an actor on every list gets through', async () => {
  const team = id => ({ actor_id: id, actor_type: 'Team', bypass_mode: 'always' });
  const app = id => ({ actor_id: id, actor_type: 'Integration', bypass_mode: 'always' });
  const classicOff = { '/repos/acme/app/branches/main': [200, { protection: { enabled: false } }] };
  const two = (a, b) =>
    read({
      ...rulesOn([ownerRule(1), ownerRule(2)], { '/repos/acme/app/rulesets/1': a, '/repos/acme/app/rulesets/2': b }),
      ...classicOff,
    });
  const cases = [
    // [first list, second list, expected state, why]
    [ruleset(1, [adminBypass]), ruleset(2, []), 'none', /lets nobody bypass/],
    [ruleset(1), ruleset(2, []), 'none', /lets nobody bypass/],
    [ruleset(1, [adminBypass]), ruleset(2), 'unknown', /admin access/],
    [
      ruleset(1, [adminBypass, team(3)]),
      ruleset(2, [adminBypass]),
      'possible',
      /^repository admins may bypass every ruleset/,
    ],
    [ruleset(1, [app(5), team(3)]), ruleset(2, [app(5)]), 'possible', /^a GitHub App may bypass/],
    // Reviewer's case: a team on one list, an app on the other. Neither is on both.
    [ruleset(1, [team(11)]), ruleset(2, [app(22)]), 'none', /lets nobody bypass/],
    [ruleset(1, [app(21)]), ruleset(2, [app(22)]), 'none', /lets nobody bypass/],
    // Admins on one, a team on the other: an admin in that team is on both. Membership decides.
    [ruleset(1, [adminBypass]), ruleset(2, [team(3)]), 'unknown', /membership/],
    [ruleset(1, [team(3)]), ruleset(2, [team(4)]), 'unknown', /membership/],
  ];
  for (const [a, b, state, why] of cases) {
    const rules = await two(a, b);
    const label = `${JSON.stringify(a[1].bypass_actors)} + ${JSON.stringify(b[1].bypass_actors)}`;
    assert.equal(rules.codeOwnerReview, 'required', label);
    assert.equal(rules.codeOwnerBypass, state, label);
    assert.match(rules.bypassWhy, why, label);
  }
  // A pull_request rule that does not require code owners has no say.
  const other = await read({
    ...rulesOn([ownerRule(1), ownerRule(2, false)], {
      '/repos/acme/app/rulesets/1': ruleset(1, [adminBypass]),
      '/repos/acme/app/rulesets/2': ruleset(2, []),
    }),
    ...classicOff,
  });
  assert.equal(other.codeOwnerBypass, 'possible');
});

test('bypass: classic protection that also requires code owners is one more list', async () => {
  const app = { actor_id: 22, actor_type: 'Integration', bypass_mode: 'always' };
  const withClassic = (actors, protection, settingsAnswer) =>
    read({
      ...rulesOn([ownerRule(7)], { '/repos/acme/app/rulesets/7': ruleset(7, actors) }),
      '/repos/acme/app/branches/main': protection,
      ...(settingsAnswer ? { '/repos/acme/app/branches/main/protection': settingsAnswer } : {}),
    });
  const settingsWith = (extra = {}, reviews = {}) => [
    200,
    {
      required_pull_request_reviews: { require_code_owner_reviews: true, ...reviews },
      enforce_admins: { enabled: true },
      ...extra,
    },
  ];
  const on = [200, { protection: { enabled: true } }];
  const cases = [
    ['classic binds everyone', [adminBypass], on, settingsWith(), 'none', /lets nobody bypass/],
    [
      'classic leaves admins out',
      [adminBypass],
      on,
      settingsWith({ enforce_admins: { enabled: false } }),
      'possible',
      /^repository admins may bypass every rule that requires it$/,
    ],
    // Reviewer's case: the app gets past the ruleset, admins past classic; nobody past both.
    ['app vs admins', [app], on, settingsWith({ enforce_admins: { enabled: false } }), 'none', /lets nobody bypass/],
    [
      'same app on both',
      [app],
      on,
      settingsWith({}, { bypass_pull_request_allowances: { apps: [{ id: 22, slug: 'bot' }] } }),
      'possible',
      /^a GitHub App may bypass every rule/,
    ],
    [
      'admins vs named team',
      [adminBypass],
      on,
      settingsWith({}, { bypass_pull_request_allowances: { teams: [{ id: 3 }] } }),
      'unknown',
      /membership/,
    ],
    [
      'classic without code owners',
      [adminBypass],
      on,
      settingsWith({}, { require_code_owner_reviews: false }),
      'possible',
      /every ruleset/,
    ],
    ['classic off', [adminBypass], [200, { protection: { enabled: false } }], undefined, 'possible', /every ruleset/],
    ['branch not protected at all', [adminBypass], [200, { protected: false }], undefined, 'possible', /every ruleset/],
    ['classic settings hidden', [adminBypass], on, [404, { message: 'Not Found' }], 'unknown', /admin access/],
    ['protection shape unknown', [adminBypass], [200, { protected: true }], undefined, 'unknown', /admin access/],
    [
      'branch read fails',
      [adminBypass],
      () => Promise.reject(new TypeError('fetch failed')),
      undefined,
      'unknown',
      /admin access/,
    ],
    ['branch 500', [adminBypass], [500, {}], undefined, 'unknown', /admin access/],
    [
      'enforce_admins missing',
      [adminBypass],
      on,
      [200, { required_pull_request_reviews: { require_code_owner_reviews: true } }],
      'unknown',
      /admins are included/,
    ],
  ];
  for (const [label, actors, protection, settingsAnswer, state, why] of cases) {
    const rules = await withClassic(actors, protection, settingsAnswer);
    assert.equal(rules.codeOwnerReview, 'required', label);
    assert.equal(rules.codeOwnerBypass, state, label);
    assert.match(rules.bypassWhy, why, label);
  }
});

test('bypass: an unread page of rules may hold a ruleset nobody can bypass', async () => {
  const github = fakeGitHub({
    '/repos/acme/app/rules/branches/main': [
      200,
      [ownerRule(7)],
      { link: '<https://elsewhere.example/next>; rel="next"' },
    ],
    '/repos/acme/app/rulesets/7': ruleset(7, [adminBypass]),
    '/repos/acme/app/branches/main': [200, { protection: { enabled: false } }],
  });
  const rules = await fetchBranchRules({ repo: 'acme/app', branch: 'main', token: 'tok', fetch: github.fetch });
  assert.equal(rules.codeOwnerReview, 'required');
  assert.equal(rules.codeOwnerBypass, 'unknown');
});

test('bypass: one request per ruleset, to the API host, with the token', async () => {
  const api = 'https://ghe.example/api/v3';
  const github = fakeGitHub(
    {
      '/repos/acme/app/rules/branches/main': [200, [ownerRule(7), ownerRule(7), { type: 'deletion', ruleset_id: 7 }]],
      '/repos/acme/app/rulesets/7': ruleset(7, []),
    },
    api,
  );
  const rules = await fetchBranchRules({
    repo: 'acme/app',
    branch: 'main',
    token: 'tok',
    apiUrl: api,
    fetch: github.fetch,
  });
  assert.equal(rules.codeOwnerBypass, 'none');
  const rulesetRequests = github.requests.filter(r => r.url.includes('/rulesets/'));
  assert.equal(rulesetRequests.length, 1, 'duplicate ruleset ids are read once');
  assert.equal(rulesetRequests[0].url, `${api}/repos/acme/app/rulesets/7`);
  assert.equal(rulesetRequests[0].headers.authorization, 'Bearer tok');
});

test('bypass: anything unreadable means unknown, and the requirement still stands', async () => {
  const failures = {
    'HTTP 500': [500, { message: 'boom' }],
    'HTTP 403': [403, { message: 'Resource not accessible by integration' }],
    'HTTP 404': [404, { message: 'Not Found' }],
    'no bypass key (non-admin token)': ruleset(7),
    'bypass list not an array': [200, { id: 7, bypass_actors: { actor_id: 5 } }],
    'not JSON': () => new Response('<html>', { status: 200 }),
    'network error': () => Promise.reject(new TypeError('fetch failed')),
    redirect: () => new Response('', { status: 301, headers: { location: 'https://evil.example/' } }),
  };
  for (const [label, answer] of Object.entries(failures)) {
    const rules = await read(rulesOn([ownerRule(7)], { '/repos/acme/app/rulesets/7': answer }));
    assert.equal(rules.codeOwnerReview, 'required', label);
    assert.equal(rules.codeOwnerBypass, 'unknown', label);
  }
});

test('bypass: ruleset ids GitHub did not give, or gave oddly, are not requested', async () => {
  for (const id of [undefined, null, '7', 7.5, -0.5, Number.MAX_SAFE_INTEGER + 2]) {
    const github = fakeGitHub(rulesOn([{ ...ownerRule(0), ruleset_id: id }]));
    const rules = await fetchBranchRules({ repo: 'acme/app', branch: 'main', fetch: github.fetch });
    assert.equal(rules.codeOwnerBypass, 'unknown', String(id));
    assert.ok(!github.requests.some(r => r.url.includes('/rulesets/')), String(id));
  }
});

test('bypass: more rulesets than the scanner reads is unknown unless one already binds everyone', async () => {
  const ids = Array.from({ length: 11 }, (_, i) => i + 1);
  // Classic protection is off, so only the eleventh, unread ruleset leaves the answer open.
  const routes = rulesOn(
    ids.map(id => ownerRule(id)),
    {
      '/repos/acme/app/branches/main': [200, { protection: { enabled: false } }],
    },
  );
  for (const id of ids) routes[`/repos/acme/app/rulesets/${id}`] = ruleset(id, [adminBypass]);
  assert.equal((await read(routes)).codeOwnerBypass, 'unknown');
  // Ten rulesets, all read, all naming admins: the same routes then say who.
  const ten = rulesOn(
    ids.slice(0, 10).map(id => ownerRule(id)),
    {
      '/repos/acme/app/branches/main': [200, { protection: { enabled: false } }],
    },
  );
  for (const id of ids.slice(0, 10)) ten[`/repos/acme/app/rulesets/${id}`] = ruleset(id, [adminBypass]);
  assert.equal((await read(ten)).codeOwnerBypass, 'possible');
  routes['/repos/acme/app/rulesets/3'] = ruleset(3, []);
  assert.equal((await read(routes)).codeOwnerBypass, 'none');
});

test('bypass: classic protection alone', async () => {
  const at = settingsBody =>
    read(
      rulesOn([], {
        '/repos/acme/app/branches/main': [200, { protection: { enabled: true } }],
        '/repos/acme/app/branches/main/protection': [200, settingsBody],
      }),
    );
  const reviews = extra => ({ require_code_owner_reviews: true, ...extra });
  const everyone = await at({
    required_pull_request_reviews: reviews({
      bypass_pull_request_allowances: { users: [{}], teams: [{}], apps: [{}] },
    }),
    enforce_admins: { enabled: false },
  });
  assert.equal(
    everyone.bypassWhy,
    'repository admins, named users, named teams and named GitHub Apps may bypass the branch protection rule that requires it',
  );
  const empty = await at({
    required_pull_request_reviews: reviews({ bypass_pull_request_allowances: { users: [], teams: [], apps: [] } }),
    enforce_admins: { enabled: true },
  });
  assert.equal(empty.codeOwnerBypass, 'none');
  assert.equal(
    (await at({ required_pull_request_reviews: reviews() })).codeOwnerBypass,
    'unknown',
    'no enforce_admins',
  );
  const apps = await at({
    required_pull_request_reviews: reviews({ bypass_pull_request_allowances: { apps: [{ slug: 'bot' }] } }),
    enforce_admins: { enabled: true },
  });
  assert.equal(apps.bypassWhy, 'named GitHub Apps may bypass the branch protection rule that requires it');
});

test('bypass: results that are not "required" carry no bypass fields', async () => {
  const notRequired = await read(
    rulesOn([ownerRule(1, false)], { '/repos/acme/app/branches/main': [200, { protection: { enabled: false } }] }),
  );
  assert.equal(notRequired.codeOwnerReview, 'not-required');
  assert.ok(!('codeOwnerBypass' in notRequired) && !('bypassWhy' in notRequired));
  const hidden = await read(rulesOn([], { '/repos/acme/app/branches/main': [200, { protection: { enabled: true } }] }));
  assert.equal(hidden.codeOwnerReview, 'unknown');
  assert.ok(!('codeOwnerBypass' in hidden));
});

// ---------------------------------------------------------------- bypass: AGC-GOV-004

const agentRepo = {
  '.claude/settings.json': settings({ allow: ['Bash(npm test:*)'] }),
  '.github/CODEOWNERS': '/.claude/ @org/platform\n',
};
const evidence = (state, why = 'repository admins may bypass the ruleset that requires it') => ({
  repo: 'acme/app',
  branch: 'main',
  codeOwnerReview: 'required',
  why: 'an active ruleset on main requires review from code owners',
  ...(state ? { codeOwnerBypass: state, bypassWhy: why } : {}),
});

test('AGC-GOV-004 bypass: needs an owner for agent configuration, as the rest of the rule does', () => {
  const gov = (files, github) => findingsFor(scanFiles(files, { github }), 'AGC-GOV-004');
  const [finding] = gov(agentRepo, evidence('possible'));
  assert.equal(finding.severity, 'low');
  assert.equal(finding.location.file, '.github/CODEOWNERS');
  assert.equal(finding.location.line, 1);
  assert.equal(
    finding.message,
    'main requires code owners to approve, but repository admins may bypass the ruleset that requires it, so a change to an agent can still merge without them.',
  );
  assert.match(finding.fix, /Do not allow bypassing the above settings/);
  assert.match(finding.fix, /Allow specified actors to bypass required pull requests/);
  assert.match(finding.fix, /Empty the bypass list of a ruleset/);
  assert.equal(
    gov({ ...agentRepo, '.github/CODEOWNERS': '/docs/ @org/docs\n' }, evidence('possible')).length,
    0,
    'owner of other files',
  );
  assert.equal(
    gov({ '.claude/settings.json': agentRepo['.claude/settings.json'] }, evidence('possible')).length,
    0,
    'no CODEOWNERS',
  );
  assert.equal(gov({ '.github/CODEOWNERS': '* @org/all\n' }, evidence('possible')).length, 0, 'no agent');
  assert.equal(gov(agentRepo, evidence(undefined)).length, 0, 'evidence from an older scanner');
});

test('AGC-GOV-004 bypass: on a pull request, reported only when the change widens an agent', () => {
  const github = evidence('possible');
  const base = scanFiles(agentRepo, { github });
  const calm = diffScans(base, scanFiles({ ...agentRepo, 'README.md': '# app\n' }, { github }));
  assert.ok(!calm.added.some(f => f.ruleId === 'AGC-GOV-004'));
  const wider = diffScans(
    base,
    scanFiles(
      { ...agentRepo, '.claude/settings.json': settings({ allow: ['Bash(npm test:*)', 'WebFetch'] }) },
      { github },
    ),
  );
  assert.ok(wider.added.some(f => f.ruleId === 'AGC-GOV-004' && /bypass/.test(f.message)));
});

test('AGC-GOV-004 bypass end to end: CLI with an admin-visible bypass list', async t => {
  const dir = mkdtempSync(join(tmpdir(), 'agc-bypass-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  mkdirSync(join(dir, '.claude'));
  mkdirSync(join(dir, '.github'));
  for (const [path, text] of Object.entries(agentRepo)) writeFileSync(join(dir, path), text);
  const run = async fetch => {
    let stdout = '';
    const code = await runCli([dir, '--format', 'json', '--github-repo', 'acme/app', '--github-branch', 'main'], {
      stdout: s => (stdout += s),
      stderr: () => {},
      cwd: dir,
      env: { GITHUB_TOKEN: 'tok' },
      fetch,
    });
    return { code, body: JSON.parse(stdout) };
  };
  const open = await run(
    fakeGitHub(
      rulesOn([ownerRule(7)], {
        '/repos/acme/app/rulesets/7': ruleset(7, [adminBypass]),
        '/repos/acme/app/branches/main': [200, { protection: { enabled: false } }],
      }),
    ).fetch,
  );
  assert.equal(open.code, 0, 'low does not fail a default run');
  assert.equal(open.body.modes.github.codeOwnerBypass, 'possible');
  assert.ok(open.body.findings.some(f => f.ruleId === 'AGC-GOV-004' && /repository admins may bypass/.test(f.message)));
  const hidden = await run(fakeGitHub(rulesOn([ownerRule(7)], { '/repos/acme/app/rulesets/7': ruleset(7) })).fetch);
  assert.equal(hidden.body.modes.github.codeOwnerBypass, 'unknown');
  assert.ok(!hidden.body.findings.some(f => f.ruleId === 'AGC-GOV-004'), 'the Actions-token case reports nothing');
});

// ---------------------------------------------------------------- options: unknown, joined, listed

const reported = (command, args, files = {}) =>
  scanFiles({ ...server(command, args), ...files })
    .findings.filter(f => f.ruleId === 'AGC-SUP-001' || f.ruleId === 'AGC-SUP-006')
    .map(f => `${f.ruleId.slice(-3)} ${(f.message.match(/(?:starts|pins|image) "([^"]+)"/) ?? [, '?'])[1]}`)
    .sort();

test('options: an unknown option followed by a word is unreadable, never guessed', () => {
  const unreadable = [
    ['npx', ['--frobnicate', 'x', 'pkg@1.2.3'], '--frobnicate', 'x'],
    ['uvx', ['--zzz', 'val', 'pkg==1.2.3'], '--zzz', 'val'],
    ['uvx', ['-Zval', 'pkg==1.2.3'], '-Z', 'val'],
    ['docker', ['run', '-i', '--brand-new', 'x', 'ghcr.io/o/mcp'], '--brand-new', 'x'],
    ['podman', ['run', '-i', '-Z', 'ghcr.io/o/mcp:1'], '-Z', 'ghcr.io/o/mcp:1'],
  ];
  for (const [command, args, option, word] of unreadable) {
    const findings = scanFiles(server(command, args)).findings.filter(f => /AGC-SUP-00[16]/.test(f.ruleId));
    const label = `${command} ${args.join(' ')}`;
    assert.deepEqual(
      findings.map(f => `${f.ruleId} ${f.severity}`),
      ['AGC-SUP-001 high'],
      label,
    );
    assert.ok(findings[0].message.includes(`${option}, an option this check does not know`), label);
    assert.ok(findings[0].message.includes(`"${word}"`), label);
    assert.match(findings[0].fix, /--option=value/, label);
  }
  // The same options are readable when nothing could be their value.
  assert.deepEqual(reported('npx', ['--frobnicate', '-y', 'pkg@1.2.3']), ['006 pkg@1.2.3']);
  assert.deepEqual(reported('npx', ['--frobnicate=x', 'pkg@1.2.3']), ['006 pkg@1.2.3']);
  assert.deepEqual(reported('docker', ['run', '--brand-new=x', 'ghcr.io/o/mcp:1']), ['006 ghcr.io/o/mcp:1']);
  // Runners whose options are not all known read an unknown option as a switch, as before.
  assert.deepEqual(reported('yarn', ['dlx', '--frobnicate', 'pkg@1.2.3']), ['006 pkg@1.2.3']);
  // A shell line keeps its own reason and fingerprint.
  const [shell] = scanFiles(server('sh', ['-c', 'npx -y a@1.0.0 && curl x'])).findings.filter(
    f => f.ruleId === 'AGC-SUP-001',
  );
  assert.match(shell.message, /starts a shell line with more than one command/);
});

test('options: listed values, joined letters and attached values are read as the programs read them', () => {
  const cases = [
    // The scorer's cases: values that used to be read as the package or image.
    [['pnpm', ['dlx', '--store-dir', '/s', 'pkg']], ['001 pkg']],
    [['docker', ['run', '--dns-opt', 'ndots:1', 'ghcr.io/o/mcp']], ['001 ghcr.io/o/mcp']],
    [['podman', ['run', '--gidmap', '0:100000:65536', 'ghcr.io/o/mcp']], ['001 ghcr.io/o/mcp']],
    [['podman', ['run', '--secret', 's', '--pod', 'p', '--arch', 'arm64', 'ghcr.io/o/mcp:1']], ['006 ghcr.io/o/mcp:1']],
    [['podman', ['run', '--tls-verify=false', '--rm', 'ghcr.io/o/mcp:1']], ['006 ghcr.io/o/mcp:1']],
    // Joined one-letter options (Docker, podman, uv).
    [['docker', ['run', '-itd', 'ghcr.io/o/mcp:1']], ['006 ghcr.io/o/mcp:1']],
    [['docker', ['run', '-iu', '1000', 'ghcr.io/o/mcp:1']], ['006 ghcr.io/o/mcp:1']],
    [['docker', ['run', '-iu1000', 'ghcr.io/o/mcp:1']], ['006 ghcr.io/o/mcp:1']],
    [['docker', ['run', '-u=1000', 'ghcr.io/o/mcp:1']], ['006 ghcr.io/o/mcp:1']],
    [['uvx', ['-qv', 'pkg==1.2.3']], ['006 pkg==1.2.3']],
    [
      ['uvx', ['-wextra==1.0', 'pkg==1.2.3']],
      ['006 extra==1.0', '006 pkg==1.2.3'],
    ],
    [
      ['uvx', ['-w=extra==1.0', 'pkg==1.2.3']],
      ['006 extra==1.0', '006 pkg==1.2.3'],
    ],
    [['uvx', ['-p3.12', 'pkg==1.2.3']], ['006 pkg==1.2.3']],
    // npm: `-p=value`, fixed-value shorthands, and `--no-<anything>`.
    [['npx', ['-p=pkg@1.2.3', 'cmd']], ['006 pkg@1.2.3']],
    [['npx', ['-dd', '-y', 'pkg@1.2.3']], ['006 pkg@1.2.3']],
    [['npx', ['--no-audit', '--no-whatever', 'pkg@1.2.3']], ['006 pkg@1.2.3']],
    // `--` ends the options.
    [['uvx', ['--', 'pkg==1.2.3']], ['006 pkg==1.2.3']],
    [['docker', ['run', '-i', '--', 'ghcr.io/o/mcp:1']], ['006 ghcr.io/o/mcp:1']],
    [['npx', ['--', '--odd-name@1.2.3']], ['006 --odd-name@1.2.3']],
  ];
  for (const [[command, args], expected] of cases)
    assert.deepEqual(reported(command, args), expected, `${command} ${args.join(' ')}`);
});

test('options: uvx --with splits on commas as uv does', () => {
  assert.deepEqual(reported('uvx', ['--with', 'a==1.0,b==2.0', 'pkg==1.2.3']), [
    '006 a==1.0',
    '006 b==2.0',
    '006 pkg==1.2.3',
  ]);
  assert.deepEqual(reported('uvx', ['--with', 'a==1.0, b', 'pkg==1.2.3']), ['001 b', '006 a==1.0', '006 pkg==1.2.3']);
  // A comma before a version operator belongs to the requirement; one inside brackets to the extras.
  assert.deepEqual(reported('uvx', ['--with', 'requests>=2.1,<3', 'pkg==1.2.3']), [
    '001 requests>=2.1,<3',
    '006 pkg==1.2.3',
  ]);
  assert.deepEqual(reported('uvx', ['--with', 'psycopg[binary,pool]==3.1.0', 'pkg==1.2.3']), [
    '006 pkg==1.2.3',
    '006 psycopg[binary,pool]==3.1.0',
  ]);
  // npm's -p is one package per option, commas and all.
  assert.deepEqual(reported('npx', ['-p', 'a@1.0.0,b@2.0.0', 'cmd']), ['001 a@1.0.0,b@2.0.0']);
});

test('pins: boundaries of what counts as a fixed version', () => {
  const sha = 'a'.repeat(40);
  const cases = [
    [['uvx', ['--from', `git+https://github.com/o/r.git@${sha}`, 'c']], [`006 git+https://github.com/o/r.git@${sha}`]],
    [
      ['uvx', ['--from', `git+https://github.com/o/r.git@${sha.toUpperCase()}`, 'c']],
      [`006 git+https://github.com/o/r.git@${sha.toUpperCase()}`],
    ],
    [
      ['uvx', ['--from', 'git+https://github.com/o/r.git@abc1234', 'c']],
      ['001 git+https://github.com/o/r.git@abc1234'],
    ],
    [
      ['uvx', ['--from', `git+https://github.com/o/r.git@${sha}0`, 'c']],
      [`001 git+https://github.com/o/r.git@${sha}0`],
    ],
    [['pipx', ['run', 'pkg@1.2.3']], ['001 pkg@1.2.3']],
    [['pipx', ['run', 'pkg==1.2.3']], ['006 pkg==1.2.3']],
    [['npx', ['-y', 'pkg@1.2']], ['001 pkg@1.2']],
    [['npx', ['-y', 'pkg@=1.2.3']], ['001 pkg@=1.2.3']],
    [['uvx', ['pkg~=1.2']], ['001 pkg~=1.2']],
    [['npx', ['--offline', 'pkg']], ['001 pkg']],
  ];
  for (const [[command, args], expected] of cases)
    assert.deepEqual(reported(command, args), expected, `${command} ${args.join(' ')}`);
  // A Python runner is never skipped for an npm dependency of the same name.
  const dep = { 'package.json': json({ devDependencies: { pkg: '1.2.3' } }) };
  assert.deepEqual(reported('uvx', ['pkg==1.2.3'], dep), ['006 pkg==1.2.3']);
  assert.deepEqual(reported('pipx', ['run', 'pkg'], dep), ['001 pkg']);
});

test('AGC-SUP-006: an extra package keeps its fingerprint across a version bump', () => {
  // The first -p names the main package, keyed by the server's name; later ones by their own name.
  const at = helper => scanFiles(server('npx', ['-y', '-p', 'pkg@1.2.3', '-p', helper, 'cmd']));
  const before = at('helper@2.0.0');
  const after = at('helper@2.0.1');
  assert.equal(findingsFor(after, 'AGC-SUP-006').length, 2);
  assert.ok(!diffScans(before, after).added.some(f => f.ruleId === 'AGC-SUP-006'), 'a bump is old debt');
  const other = scanFiles(server('npx', ['-y', '-p', 'pkg@1.2.3', '-p', 'other@2.0.0', 'cmd']));
  assert.ok(
    diffScans(before, other).added.some(f => f.ruleId === 'AGC-SUP-006' && /other@2.0.0/.test(f.message)),
    'a new package is new',
  );
});

test('AGC-SUP-006: servers in a workflow step, and the fingerprint they share by name', () => {
  const workflow = steps =>
    `on: issue_comment\npermissions:\n  contents: read\njobs:\n  c:\n    runs-on: ubuntu-latest\n    steps:\n${steps
      .map(
        path =>
          `      - uses: anthropics/claude-code-action@v1\n        with:\n          claude_args: --mcp-config ${path} --allowedTools mcp__gh\n`,
      )
      .join('')}`;
  const one = scanFiles({
    '.github/workflows/c.yml': workflow(['.github/a.json']),
    '.github/a.json': mcp({ gh: { command: 'npx', args: ['-y', 'pkg@1.2.3'] } }),
  });
  const [finding] = findingsFor(one, 'AGC-SUP-006');
  assert.ok(finding, 'a workflow server is checked');
  assert.match(finding.message, /pins "pkg@1.2.3"/);
  // Two steps, each with a server named "gh" in its own config file: both are reported, each at
  // its file. (Two servers of one name in one file share a fingerprint, so a version bump is not new.)
  const two = scanFiles({
    '.github/workflows/c.yml': workflow(['.github/a.json', '.github/b.json']),
    '.github/a.json': mcp({ gh: { command: 'npx', args: ['-y', 'pkg@1.2.3'] } }),
    '.github/b.json': mcp({ gh: { command: 'npx', args: ['-y', 'pkg@2.0.0'] } }),
  });
  const found = findingsFor(two, 'AGC-SUP-006');
  assert.deepEqual(found.map(f => `${f.location.file} ${f.message.match(/pins "([^"]+)"/)[1]}`).sort(), [
    '.github/a.json pkg@1.2.3',
    '.github/b.json pkg@2.0.0',
  ]);
  assert.equal(new Set(found.map(f => f.fingerprint)).size, 2);
});

test('bypass: a requiring rule GitHub gave no ruleset id for leaves the answer open', async () => {
  const rules = await read({
    ...rulesOn([ownerRule(7), { ...ownerRule(0), ruleset_id: undefined }], {
      '/repos/acme/app/rulesets/7': ruleset(7, [adminBypass]),
    }),
    '/repos/acme/app/branches/main': [200, { protection: { enabled: false } }],
  });
  assert.equal(rules.codeOwnerReview, 'required');
  assert.equal(rules.codeOwnerBypass, 'unknown');
  // An empty list among those read still settles it.
  const settled = await read({
    ...rulesOn([ownerRule(7), { ...ownerRule(0), ruleset_id: undefined }], {
      '/repos/acme/app/rulesets/7': ruleset(7, []),
    }),
  });
  assert.equal(settled.codeOwnerBypass, 'none');
});

test('bypass: actors GitHub identifies by type alone, and apps by id', async () => {
  // As GitHub returns them: a deploy key's actor_id is null, an organization admin's is ignored.
  const key = { actor_id: null, actor_type: 'DeployKey', bypass_mode: 'always' };
  const orgAdmin = id => ({ actor_id: id, actor_type: 'OrganizationAdmin', bypass_mode: 'always' });
  const app = id => ({ actor_id: id, actor_type: 'Integration', bypass_mode: 'always' });
  const routes = (a, b) => ({
    ...rulesOn([ownerRule(1), ownerRule(2)], {
      '/repos/acme/app/rulesets/1': ruleset(1, a),
      '/repos/acme/app/rulesets/2': ruleset(2, b),
    }),
    '/repos/acme/app/branches/main': [200, { protection: { enabled: false } }],
  });
  const cases = [
    [[key], [adminBypass], 'none', 'a key is not a person on the admins list'],
    [[key], [key, adminBypass], 'possible', 'deploy keys'],
    [[orgAdmin(1)], [orgAdmin(null)], 'possible', 'organization admins'],
    [[app(21)], [app(22)], 'none', 'two different apps'],
    [[app(21)], [app(21)], 'possible', 'a GitHub App'],
  ];
  for (const [a, b, state, note] of cases) {
    const rules = await read(routes(a, b));
    assert.equal(rules.codeOwnerBypass, state, note);
    if (state === 'possible') assert.match(rules.bypassWhy, new RegExp(`^${note} may bypass`), note);
  }
});

test('option lists match npm’s own definitions', t => {
  const root = spawnSync('npm', ['root', '-g'], { encoding: 'utf8' }).stdout?.trim();
  const version = spawnSync('npm', ['--version'], { encoding: 'utf8' }).stdout?.trim() ?? '';
  const file = root && join(root, 'npm', 'node_modules', '@npmcli', 'config', 'lib', 'definitions', 'index.js');
  if (!file || !existsSync(file) || !version.startsWith('11.'))
    return t.skip(`npm 11 not found (have ${version || 'none'})`);
  const { definitions } = createRequire(import.meta.url)(file);
  const npm = FLAG_TABLES.npm;
  for (const [name, definition] of Object.entries(definitions)) {
    const types = [definition.type].flat();
    const takes = !types.includes(Boolean) || types.includes(String);
    const known = takes ? npm.valued.has(`--${name}`) || npm.main.has(`--${name}`) : npm.plain.has(`--${name}`);
    assert.ok(known, `--${name} (${takes ? 'takes a value' : 'a switch'}) missing from the npm table`);
  }
});

test('option lists match docker run --help', t => {
  const help = spawnSync('docker', ['run', '--help'], { encoding: 'utf8' });
  if (help.status !== 0 || !help.stdout) return t.skip('docker not installed');
  const run = FLAG_TABLES.run;
  let checked = 0;
  for (const line of help.stdout.split('\n')) {
    // Value types are words like `list`, `uint16`, `gpu-request`, `bytes`.
    const match = /^\s+(?:(-\w), )?(--[a-z0-9-]+)(?: ([a-zA-Z0-9:-]+))?\s{2,}/.exec(line);
    if (!match) continue;
    const [, short, long, value] = match;
    for (const name of [short, long].filter(Boolean)) {
      checked += 1;
      assert.ok(
        value ? run.valued.has(name) : run.plain.has(name),
        `${name} (${value ? 'takes a value' : 'a switch'})`,
      );
    }
  }
  assert.ok(checked >= 100, `read ${checked} options from docker run --help`);
});

// ---------------------------------------------------------------- second review: real program behaviour

test('project install: npx runs the installed copy only for a bare name or the exact installed version', () => {
  const dep = version => ({ 'package.json': json({ devDependencies: { pkg: version } }) });
  const cases = [
    // [declared, spec, expected]
    ['1.0.0', 'pkg', []],
    ['1.0.0', 'pkg@1.0.0', []],
    ['1.0.0', 'pkg@2.0.0', ['006 pkg@2.0.0']],
    ['1.0.0', 'pkg@latest', ['001 pkg@latest']],
    ['1.0.0', 'pkg@^3.0.0', ['001 pkg@^3.0.0']],
    // A range in package.json does not say which version the lockfile installed.
    ['^1.0.0', 'pkg@1.0.0', ['006 pkg@1.0.0']],
    ['^1.0.0', 'pkg', []],
  ];
  for (const [declared, spec, expected] of cases) {
    assert.deepEqual(reported('npx', ['-y', spec], dep(declared)), expected, `${declared} / npx ${spec}`);
    // bunx: the project's copy for a bare name only; any version, range or tag is fetched.
    // An exact version is pinned (AGC-SUP-006); a range or a tag is not (AGC-SUP-001).
    const bunx = spec === 'pkg' ? [] : [`${/@\d/.test(spec) ? '006' : '001'} ${spec}`];
    assert.deepEqual(reported('bunx', [spec], dep(declared)), bunx, `${declared} / bunx ${spec}`);
  }
});

test('npx and npm exec read options by their own rules', () => {
  const cases = [
    // npx drops the removed -n, --npm and --node-arg with their values (npm bin/npx-cli.js).
    [['npx', ['-n', '--max-old-space-size=4096', 'pkg@1.2.3']], ['006 pkg@1.2.3']],
    [['npx', ['--node-arg', 'x', '-y', 'pkg@1.2.3']], ['006 pkg@1.2.3']],
    // For npm exec, -n is --no-yes: only an installed copy runs.
    [['npm', ['exec', '-n', '--', 'pkg@1.2.3']], []],
    // Every way to say "do not download".
    [['npx', ['--no-yes', 'pkg@1.2.3']], []],
    [['npx', ['--yes=false', 'pkg']], []],
    [['npx', ['--no', 'pkg']], []],
    [['npx', ['--no-install', 'pkg']], []],
    // --browser takes a value in npm exec (a string is allowed), not in npx (a switch is allowed).
    [['npm', ['exec', '--browser', 'firefox', '--', 'pkg@1.2.3']], ['006 pkg@1.2.3']],
    // Only npm runners read --no-install as "installed only"; other runners fetch as usual.
    [['pnpm', ['dlx', '--no-install', 'pkg@1.2.3']], ['006 pkg@1.2.3']],
    [['uvx', ['--offline', 'pkg==1.2.3']], ['006 pkg==1.2.3']],
  ];
  for (const [[command, args], expected] of cases)
    assert.deepEqual(reported(command, args), expected, `${command} ${args.join(' ')}`);
});

test('uv options read from uv’s own source, including hidden ones', () => {
  const cases = [
    [['uvx', ['--native-tls', 'pkg==1.0.0']], ['006 pkg==1.0.0']],
    [['uvx', ['--system-certs', '--no-progress', 'pkg==1.0.0']], ['006 pkg==1.0.0']],
    [['uvx', ['--directory', '/srv', '--with-editable', './lib', 'pkg==1.0.0']], ['006 pkg==1.0.0']],
    [['uvx', ['--index-url', 'https://i.example/simple', '-f', '/wheels', 'pkg==1.0.0']], ['006 pkg==1.0.0']],
    [['uvx', ['--reinstall', '-U', '--refresh-package', 'x', 'pkg==1.0.0']], ['006 pkg==1.0.0']],
    [['uvx', ['--python-preference', 'only-system', 'pkg==1.0.0']], ['006 pkg==1.0.0']],
    [['uvx', ['--from=', 'cmd']], ['001 cmd']],
    [['npx', ['-p', '', 'cmd']], ['001 cmd']],
  ];
  for (const [[command, args], expected] of cases)
    assert.deepEqual(reported(command, args), expected, `${command} ${args.join(' ')}`);
});

test('PEP 508 sources and environment markers', () => {
  const sha = 'b'.repeat(40);
  const digest = 'c'.repeat(64);
  const cases = [
    [
      ['uvx', ['--from', `pkg @ git+https://github.com/o/r@${sha}`, 'cmd']],
      [`006 pkg @ git+https://github.com/o/r@${sha}`],
    ],
    [
      ['uvx', ['--from', 'pkg @ git+https://github.com/o/r@main', 'cmd']],
      ['001 pkg @ git+https://github.com/o/r@main'],
    ],
    [
      ['uvx', ['--from', `pkg @ https://x.example/pkg-1.0-py3-none-any.whl#sha256=${digest}`, 'cmd']],
      [`006 pkg @ https://x.example/pkg-1.0-py3-none-any.whl#sha256=${digest}`],
    ],
    [
      ['uvx', ['--from', 'pkg @ https://x.example/pkg-1.0-py3-none-any.whl', 'cmd']],
      ['001 pkg @ https://x.example/pkg-1.0-py3-none-any.whl'],
    ],
    [
      ['uvx', ['--with', "a==1.0; python_version<'3.12'", 'pkg==1.0.0']],
      ["006 a==1.0; python_version<'3.12'", '006 pkg==1.0.0'],
    ],
    [
      ['uvx', ['--with', "a>=1.0; python_version<'3.12'", 'pkg==1.0.0']],
      ["001 a>=1.0; python_version<'3.12'", '006 pkg==1.0.0'],
    ],
  ];
  for (const [[command, args], expected] of cases)
    assert.deepEqual(reported(command, args), expected, `${command} ${args.join(' ')}`);
});

test('podman and docker: options of their own, container run, global options, --rootfs', () => {
  const cases = [
    [['podman', ['run', '--chrootdirs', '/x', '--http-proxy', '-i', 'ghcr.io/o/mcp:1']], ['006 ghcr.io/o/mcp:1']],
    [['podman', ['run', '--rootfs', '/srv/root', 'cmd']], []],
    [['docker', ['container', 'run', '-i', 'ghcr.io/o/mcp:1']], ['006 ghcr.io/o/mcp:1']],
    [['docker', ['--context', 'remote', 'run', '-i', 'ghcr.io/o/mcp:1']], ['006 ghcr.io/o/mcp:1']],
    [['docker', ['-H', 'ssh://h', '--tls', 'container', 'run', 'ghcr.io/o/mcp']], ['001 ghcr.io/o/mcp']],
    [['podman', ['--connection', 'm', 'run', 'ghcr.io/o/mcp:1']], ['006 ghcr.io/o/mcp:1']],
    [['docker', ['run', '-iu=1000', 'ghcr.io/o/mcp:1']], ['006 ghcr.io/o/mcp:1']],
    [['docker', ['ps']], []],
  ];
  for (const [[command, args], expected] of cases)
    assert.deepEqual(reported(command, args), expected, `${command} ${args.join(' ')}`);
  const [unknown] = scanFiles(server('docker', ['--frobnicate', 'x', 'run', 'ghcr.io/o/mcp'])).findings.filter(
    f => f.ruleId === 'AGC-SUP-001',
  );
  assert.match(unknown.message, /starts docker with --frobnicate, an option this check does not know/);
});

test('duplicates are reported once', () => {
  assert.deepEqual(reported('uvx', ['--with', 'pkg==1.2.3', 'pkg==1.2.3']), ['006 pkg==1.2.3']);
  assert.deepEqual(reported('npx', ['-p', 'a', '-p', 'b@1.0.0', '-p', 'b@1.0.0', 'cmd']), ['001 a', '006 b@1.0.0']);
});

test('AGC-SUP-001 fingerprints: a shell line and an unknown option are keyed apart, and stay put', () => {
  const key = (finding, subject) =>
    createHash('sha256')
      .update(`AGC-SUP-001\0${finding.agentId ?? ''}\0${finding.location.file}\0${subject}`)
      .digest('hex')
      .slice(0, 20);
  const launch = args => ({ command: 'sh', args });
  const shellServer = { command: 'sh', args: ['-c', 'npx -y a@1.0.0 && curl x'] };
  const optionServer = { command: 'npx', args: ['--frobnicate', 'x', 'pkg'] };
  const serverKey = s =>
    `s@${createHash('sha256')
      .update([s.command, ...s.args, ''].join('\0'))
      .digest('hex')
      .slice(0, 12)}`;
  const [shell] = findingsFor(scanFiles({ '.mcp.json': mcp({ s: shellServer }) }), 'AGC-SUP-001');
  const [option] = findingsFor(scanFiles({ '.mcp.json': mcp({ s: optionServer }) }), 'AGC-SUP-001');
  assert.equal(shell.fingerprint, key(shell, `server:${serverKey(shellServer)}:shell`));
  assert.equal(option.fingerprint, key(option, `server:${serverKey(optionServer)}:options`));
  void launch;
});

test('bypass: contradicting answers and malformed settings are unknown', async () => {
  const contradicting = await read({
    ...rulesOn([ownerRule(7)], {
      '/repos/acme/app/rulesets/7': [200, { id: 7, bypass_actors: [], current_user_can_bypass: 'always' }],
    }),
    '/repos/acme/app/branches/main': [200, { protection: { enabled: false } }],
  });
  assert.equal(contradicting.codeOwnerBypass, 'unknown');
  const consistent = await read(
    rulesOn([ownerRule(7)], {
      '/repos/acme/app/rulesets/7': [200, { id: 7, bypass_actors: [], current_user_can_bypass: 'never' }],
    }),
  );
  assert.equal(consistent.codeOwnerBypass, 'none');
  const odd = await read(
    rulesOn([], {
      '/repos/acme/app/branches/main': [200, { protection: { enabled: true } }],
      '/repos/acme/app/branches/main/protection': [
        200,
        { required_pull_request_reviews: { require_code_owner_reviews: true }, enforce_admins: { enabled: 'yes' } },
      ],
    }),
  );
  assert.equal(odd.codeOwnerBypass, 'unknown');
});

test('CLI end to end: --base and a baseline file for AGC-SUP-006 and the bypass finding', async t => {
  const dir = mkdtempSync(join(tmpdir(), 'agc-e2e-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const git = (...args) =>
    spawnSync(
      'git',
      ['-C', dir, '-c', 'user.name=t', '-c', 'user.email=t@example.com', '-c', 'commit.gpgsign=false', ...args],
      {
        encoding: 'utf8',
      },
    );
  const write = (path, text) => {
    mkdirSync(join(dir, path, '..'), { recursive: true });
    writeFileSync(join(dir, path), text);
  };
  const github = fakeGitHub(
    rulesOn([ownerRule(7)], {
      '/repos/acme/app/rulesets/7': ruleset(7, [adminBypass]),
      '/repos/acme/app/branches/main': [200, { protection: { enabled: false } }],
    }),
  );
  const run = async (...args) => {
    let stdout = '';
    const code = await runCli([dir, '--format', 'json', '--fail-on', 'low', ...args], {
      stdout: s => (stdout += s),
      stderr: () => {},
      cwd: dir,
      env: { GITHUB_TOKEN: 'tok' },
      fetch: github.fetch,
    });
    return { code, body: stdout.trimStart().startsWith('{') ? JSON.parse(stdout) : undefined };
  };
  write('.claude/settings.json', settings({ allow: ['Bash(npm test:*)'] }));
  write('.github/CODEOWNERS', '/.claude/ @org/platform\n/.mcp.json @org/platform\n');
  write('.mcp.json', mcp({ s: { command: 'npx', args: ['-y', 'pkg@1.2.3'] } }));
  git('init', '-q', '-b', 'main');
  git('add', '.');
  git('commit', '-q', '-m', 'base');
  const gh = ['--github-repo', 'acme/app', '--github-branch', 'main'];
  // Unchanged: both findings exist but neither is new.
  const same = await run('--base', 'main', ...gh);
  assert.ok(same.body.findings.some(f => f.ruleId === 'AGC-SUP-006'));
  assert.ok(!same.body.diff.added.length, 'nothing new on an unchanged branch');
  assert.equal(same.code, 0);
  // A change that bumps the pin and widens the agent: the bypass finding becomes new, SUP-006 does not.
  write('.mcp.json', mcp({ s: { command: 'npx', args: ['-y', 'pkg@1.2.4'] } }));
  write('.claude/settings.json', settings({ allow: ['Bash(npm test:*)', 'WebFetch'] }));
  const wider = await run('--base', 'main', ...gh);
  const added = new Set(wider.body.diff.added);
  const byRule = id => wider.body.findings.filter(f => f.ruleId === id && added.has(f.fingerprint));
  assert.equal(byRule('AGC-SUP-006').length, 0, 'a version bump is old debt');
  assert.equal(byRule('AGC-GOV-004').length, 1);
  assert.match(byRule('AGC-GOV-004')[0].message, /repository admins may bypass/);
  // A baseline written now hides both; a new pinned server still fails at --fail-on low.
  assert.equal((await run('--write-baseline', 'agc-baseline.json', ...gh)).code, 0);
  assert.equal((await run('--baseline', 'agc-baseline.json', ...gh)).code, 0);
  write(
    '.mcp.json',
    mcp({ s: { command: 'npx', args: ['-y', 'pkg@1.2.4'] }, t: { command: 'uvx', args: ['other==2.0.0'] } }),
  );
  const fresh = await run('--baseline', 'agc-baseline.json', ...gh);
  assert.equal(fresh.code, 1);
  assert.deepEqual(
    fresh.body.findings.filter(f => f.ruleId === 'AGC-SUP-006').map(f => f.message.match(/pins "([^"]+)"/)[1]),
    ['other==2.0.0'],
  );
});

// The tables for programs not installed here are checked when they are.
for (const [program, args, table, pattern] of [
  ['uv', ['tool', 'run', '--help'], 'uv', /^\s+(?:(-\w), )?(--[a-z0-9-]+)(?: <([A-Z_]+)>)?/],
  ['podman', ['run', '--help'], 'run', /^\s+(?:(-\w), )?(--[a-z0-9-]+)(?: ([a-zA-Z0-9:-]+))?\s{2,}/],
]) {
  test(`option list matches ${program} ${args.join(' ')}`, t => {
    const help = spawnSync(program, args, { encoding: 'utf8' });
    if (help.error || help.status !== 0) return t.skip(`${program} not installed`);
    const tableOf = FLAG_TABLES[table];
    let checked = 0;
    for (const line of help.stdout.split('\n')) {
      const match = pattern.exec(line);
      if (!match) continue;
      const [, short, long, value] = match;
      for (const name of [short, long].filter(Boolean)) {
        checked += 1;
        const known = value
          ? tableOf.valued.has(name) || tableOf.main.has(name) || tableOf.extra.has(name)
          : tableOf.plain.has(name);
        assert.ok(known, `${name} (${value ? 'takes a value' : 'a switch'})`);
      }
    }
    assert.ok(checked > 30, `read ${checked} options from the help`);
  });
}

// ---------------------------------------------------------------- third review: npm's own behaviour

test('installed-only options: by runner, and the last one wins', () => {
  const cases = [
    // npm exec does not know --no-install ("Unknown cli config"): it fetches.
    [['npm', ['exec', '--no-install', '--', 'pkg']], ['001 pkg']],
    [['npm', ['exec', '--no', '--', 'pkg']], []],
    // npm reads the last value of --yes.
    [['npx', ['--no-install', '-y', 'pkg']], ['001 pkg']],
    [['npx', ['--no', '--yes', 'pkg']], ['001 pkg']],
    [['npx', ['-y', '--no-install', 'pkg']], []],
    [['npx', ['--yes=true', '--yes=false', 'pkg']], []],
    // After the package the words are the server's.
    [['npx', ['-y', 'pkg@1.2.3', '--no-install']], ['006 pkg@1.2.3']],
  ];
  for (const [[command, args], expected] of cases)
    assert.deepEqual(reported(command, args), expected, `${command} ${args.join(' ')}`);
});

test('npm exec reads options anywhere before --; npx stops at the package', () => {
  const cases = [
    [['npm', ['exec', '--yes', 'pkg@1.2.3', '--package=evil']], ['001 evil']],
    [['npm', ['exec', '--yes', '--', 'pkg@1.2.3', '--package=evil']], ['006 pkg@1.2.3']],
    [['npx', ['-y', 'pkg@1.2.3', '--package=evil']], ['006 pkg@1.2.3']],
    // -p is --parseable for npm exec and --package for npx.
    [['npm', ['exec', '-p', '--yes', '--', 'semver@7.6.0']], ['006 semver@7.6.0']],
    // Run on npm 11.20: this runs semver, with -p as --parseable.
    [['npm', ['exec', '--yes', '-p', 'semver@7.6.0', '--', '1.2.3']], ['006 semver@7.6.0']],
    [['npx', ['-p', 'semver@7.6.0', 'semver']], ['006 semver@7.6.0']],
  ];
  for (const [[command, args], expected] of cases)
    assert.deepEqual(reported(command, args), expected, `${command} ${args.join(' ')}`);
});

test('project install: a range an installed version satisfies runs that copy', () => {
  const dep = version => ({ 'package.json': json({ devDependencies: { pkg: version } }) });
  assert.deepEqual(reported('npx', ['-y', 'pkg@^1.0.0'], dep('1.2.3')), []);
  assert.deepEqual(reported('npx', ['-y', 'pkg@~1.2.0'], dep('1.2.3')), []);
  assert.deepEqual(reported('npx', ['-y', 'pkg@>=2'], dep('1.2.3')), ['001 pkg@>=2']);
  assert.deepEqual(reported('npx', ['-y', 'pkg@latest'], dep('1.2.3')), ['001 pkg@latest'], 'a tag is always fetched');
  // From the lockfile, at any depth, and only versions it records.
  const lock = {
    'package.json': json({ devDependencies: { other: '1.0.0' } }),
    'package-lock.json': json({
      lockfileVersion: 3,
      packages: {
        '': { name: 'app' },
        'node_modules/other': { version: '1.0.0' },
        'node_modules/other/node_modules/pkg': { version: '1.4.0' },
        'node_modules/alias': { name: 'aliased', version: '3.0.0' },
        'node_modules/linked': { link: true, resolved: 'packages/linked' },
        'packages/linked': { name: 'linked', version: '0.3.0' },
        'node_modules/dangling': { link: true, resolved: 'packages/gone' },
      },
    }),
  };
  assert.deepEqual(reported('npx', ['-y', 'pkg@^1.3.0'], lock), []);
  assert.deepEqual(reported('npx', ['-y', 'pkg@1.4.0'], lock), []);
  assert.deepEqual(reported('npx', ['-y', 'pkg@2.0.0'], lock), ['006 pkg@2.0.0']);
  assert.deepEqual(reported('npx', ['-y', 'pkg'], lock), []);
  assert.deepEqual(reported('npx', ['-y', 'aliased@3.0.0'], lock), [], 'an alias is found by its real name');
  assert.deepEqual(reported('npx', ['-y', 'alias@3.0.0'], lock), ['006 alias@3.0.0']);
  assert.deepEqual(reported('npx', ['-y', 'linked'], lock), [], 'a workspace link is installed');
  assert.deepEqual(reported('npx', ['-y', 'linked@0.3.0'], lock), [], 'at its target version');
  assert.deepEqual(reported('npx', ['-y', 'dangling'], lock), ['001 dangling'], 'a link to nothing is not');
  // A broken lockfile leaves the versions unknown and reports nothing about itself.
  const broken = scanFiles({ ...server('npx', ['-y', 'pkg@1.0.0']), 'package-lock.json': '{ not json' });
  assert.deepEqual(
    broken.findings.filter(f => f.location.file === 'package-lock.json'),
    [],
  );
  assert.equal(findingsFor(broken, 'AGC-SUP-006').length, 1);
});

test('lockfileVersions: v1, v2 and v3 shapes', () => {
  assert.deepEqual(
    lockfileVersions({
      lockfileVersion: 1,
      dependencies: { a: { version: '1.0.0', dependencies: { b: { version: '2.0.0' } } }, c: { version: 'file:../c' } },
    }),
    [
      ['a', '1.0.0'],
      ['b', '2.0.0'],
    ],
  );
  assert.deepEqual(
    lockfileVersions({ packages: { '': { version: '9.9.9' }, 'node_modules/@s/x': { version: '1.0.0' } } }),
    [['@s/x', '1.0.0']],
  );
  assert.deepEqual(lockfileVersions(null), []);
  assert.deepEqual(lockfileVersions({ packages: { 'node_modules/a': 'x' } }), []);
});

test('AGC-SUP-006 fingerprints: keyed by package name, whichever position it is in', () => {
  const at = args => scanFiles(server('npx', args));
  const added = (a, b) =>
    diffScans(at(a), at(b))
      .added.filter(f => f.ruleId === 'AGC-SUP-006')
      .map(f => f.message.match(/pins "([^"]+)"/)[1]);
  assert.deepEqual(added(['-y', 'good@1.0.0'], ['-y', 'evil@1.0.0']), ['evil@1.0.0'], 'another package is new');
  assert.deepEqual(added(['-y', 'good@1.0.0'], ['-y', 'good@1.0.1']), [], 'a new version is not');
  assert.deepEqual(
    added(['-p', 'a@1.0.0', '-p', 'b@1.0.0', 'cmd'], ['-p', 'b@1.0.0', '-p', 'a@1.0.0', 'cmd']),
    [],
    'nor a new order',
  );
});

test('third review: remaining branches', async () => {
  const cases = [
    [
      ['uvx', ['--from', `pkg @ https://x.example/p.whl#sha256=${'c'.repeat(63)}`, 'c']],
      [`001 pkg @ https://x.example/p.whl#sha256=${'c'.repeat(63)}`],
    ],
    [
      ['uvx', ['--from', `pkg @ https://x.example/p.whl#sha256=${'c'.repeat(65)}`, 'c']],
      [`001 pkg @ https://x.example/p.whl#sha256=${'c'.repeat(65)}`],
    ],
    [['yarn', ['dlx', '-qp', 'pkg@1.2.3', 'cmd']], ['006 pkg@1.2.3']],
    [['bunx', ['-p=pkg@1.0.0', 'cmd']], ['006 pkg@1.0.0']],
    [['pnpm', ['dlx', '-sc', 'pkg@1.2.3']], ['006 pkg@1.2.3']],
    [['pipx', ['run', '--spec=pkg==1.0', 'cmd']], ['006 pkg==1.0']],
    [['npx', ['-y', 'link:../pkg']], []],
    [['npx', ['-y', 'workspace:pkg']], []],
    // Launchers neither rule used to see.
    [['docker.exe', ['run', '-i', 'ghcr.io/o/mcp:1']], ['006 ghcr.io/o/mcp:1']],
    [['cmd', ['/c', 'docker', 'run', '-i', 'ghcr.io/o/mcp:1']], ['006 ghcr.io/o/mcp:1']],
    [['sh', ['-c', 'exec docker run -i ghcr.io/o/mcp']], ['001 ghcr.io/o/mcp']],
    [['uv', ['tool', 'run', 'pkg==1.0']], ['006 pkg==1.0']],
    [['uv', ['tool', 'run', 'pkg@1.0']], ['006 pkg@1.0']],
    [['bash', ['-c', 'exec npx -y pkg@1.2.3']], ['006 pkg@1.2.3']],
    [['docker', ['--cloud', 'run', '-i', 'ghcr.io/o/mcp:1']], ['006 ghcr.io/o/mcp:1']],
  ];
  for (const [[command, args], expected] of cases)
    assert.deepEqual(reported(command, args), expected, `${command} ${args.join(' ')}`);
  const [fix] = findingsFor(scanFiles(server('uv', ['tool', 'run', 'pkg==1.0'])), 'AGC-SUP-006');
  assert.match(fix.fix, /locked environment/);
  // GitHub: a request that fails among others, a non-200 with a list, and every contradicting answer.
  const twoRulesets = (first, second) =>
    read({
      ...rulesOn([ownerRule(1), ownerRule(2)], {
        '/repos/acme/app/rulesets/1': first,
        '/repos/acme/app/rulesets/2': second,
      }),
      '/repos/acme/app/branches/main': [200, { protection: { enabled: false } }],
    });
  const network = () => Promise.reject(new TypeError('fetch failed'));
  assert.equal((await twoRulesets(network, ruleset(2, [adminBypass]))).codeOwnerBypass, 'unknown');
  assert.equal((await twoRulesets(ruleset(1, [adminBypass]), network)).codeOwnerBypass, 'unknown');
  assert.equal(
    (await twoRulesets([500, { id: 1, bypass_actors: [] }], ruleset(2, [adminBypass]))).codeOwnerBypass,
    'unknown',
  );
  for (const mayBypass of ['always', 'pull_requests_only', 'exempt'])
    assert.equal(
      (
        await twoRulesets(
          [200, { id: 1, bypass_actors: [], current_user_can_bypass: mayBypass }],
          ruleset(2, [adminBypass]),
        )
      ).codeOwnerBypass,
      'unknown',
      mayBypass,
    );
});

test('option lists: npm shorthands and docker’s own options', t => {
  const root = spawnSync('npm', ['root', '-g'], { encoding: 'utf8' }).stdout?.trim();
  const file = root && join(root, 'npm', 'node_modules', '@npmcli', 'config', 'lib', 'definitions', 'index.js');
  if (file && existsSync(file)) {
    const { definitions, shorthands } = createRequire(import.meta.url)(file);
    const types = name => [definitions[name]?.type].flat();
    for (const [short, expansion] of Object.entries(shorthands)) {
      const name = (short.length === 1 ? '-' : '--') + short;
      // A negation (`--no-global`) or a fixed value (`--loglevel info`) is a switch.
      const single =
        expansion.length === 1 && !expansion[0].startsWith('--no-') ? expansion[0].replace(/^--/, '') : undefined;
      // nopt (npm exec): a single option keeps its own reading; a fixed value is one word.
      const npmTakes = single !== undefined && (!types(single).includes(Boolean) || types(single).includes(String));
      if (name !== '-p')
        assert.equal(FLAG_TABLES.npm.valued.has(name), npmTakes, `npm exec ${name} → ${expansion.join(' ')}`);
    }
    // npx's own reading is compared with npm's npx-cli.js in its own test.
    assert.ok(!FLAG_TABLES.npm.main.has('-p'));
  } else t.diagnostic('npm definitions not found');
  const help = spawnSync('docker', ['--help'], { encoding: 'utf8' });
  if (help.status !== 0) return t.skip('docker not installed');
  let checked = 0;
  for (const line of help.stdout.split('\n')) {
    const match = /^\s+(?:(-\w), )?(--[a-z0-9-]+)(?: ([a-zA-Z0-9:-]+)(\[=[^\]]*\])?)?\s{2,}/.exec(line);
    if (!match) continue;
    const [, short, long, value, optional] = match;
    for (const name of [short, long].filter(Boolean)) {
      checked += 1;
      const takes = value !== undefined && optional === undefined;
      assert.ok(
        takes ? FLAG_TABLES.container.valued.has(name) : FLAG_TABLES.container.plain.has(name),
        `docker ${name}`,
      );
    }
  }
  assert.ok(checked >= 10, `read ${checked} options from docker --help`);
});

// ---------------------------------------------------------------- fourth review: npx as npm wrote it

/** npm's own bin/npx-cli.js, run with its final hand-over to npm stubbed: what it passes to npm exec. */
function realNpx() {
  const root = spawnSync('npm', ['root', '-g'], { encoding: 'utf8' }).stdout?.trim();
  const file = root && join(root, 'npm', 'bin', 'npx-cli.js');
  if (!file || !existsSync(file)) return undefined;
  const source = readFileSync(file, 'utf8').replace(/^#!.*\n/, '');
  const real = createRequire(file);
  return args => {
    let handed;
    const require = Object.assign(id => (id === '../lib/cli.js' ? proc => (handed = proc.argv.slice(3)) : real(id)), {
      resolve: real.resolve,
    });
    const proc = { argv: ['node', 'npx', ...args] };
    new Function('require', 'process', 'console', source)(require, proc, { error() {}, log() {} });
    return handed;
  };
}

test('npxArgv matches npm’s own npx-cli.js on generated command lines', t => {
  const npx = realNpx();
  if (!npx) return t.skip('npm’s npx-cli.js not found');
  const words = [
    '-y',
    '--yes',
    '--yes=false',
    '-p',
    '-p=a@1.0.0',
    '-pfoo',
    '--p=bar',
    '--package',
    '--package=evil',
    'pkg@1.0.0',
    'pkg',
    'x',
    '--no-color',
    '--no-audit',
    '--no-install',
    '--no',
    '-n',
    '--npm',
    '--node-arg',
    '--registry',
    'https://r.example',
    '-c',
    'echo hi',
    '--call',
    '--shell',
    'sh',
    '-d',
    '-dd',
    '-w',
    'api',
    '--cache',
    '/c',
    '--frobnicate',
    'val',
    '-q',
    '--quiet',
    '--',
    '-',
    '--loglevel=warn',
    '--browser',
    '-yq',
    '--always-spawn',
  ];
  let seed = 7;
  const random = n => ((seed = (seed * 1103515245 + 12345) % 2 ** 31), seed % n);
  let compared = 0;
  for (let round = 0; round < 20_000; round += 1) {
    const args = Array.from({ length: random(7) }, () => words[random(words.length)]);
    assert.deepEqual(npxArgv(args), npx(args), JSON.stringify(args));
    compared += 1;
  }
  assert.equal(compared, 20_000);
});

test('npx: the options npx-cli swallows, and what npm exec then runs', () => {
  const cases = [
    // npx-cli counts --no-color as taking a value: pkg@1.0.0 is its value, and npm exec then reads
    // --package=evil as the package to install.
    [['npx', ['--no-color', 'pkg@1.0.0', '--package=evil']], ['001 evil']],
    [['npx', ['--no-audit', '--no-fund', 'pkg@1.0.0']], ['006 pkg@1.0.0']],
    // npm then reads --no-color as a switch, so pkg@1.0.0 is still the package.
    [['npx', ['--no-color', 'pkg@1.0.0']], ['006 pkg@1.0.0']],
    // npx-cli takes x as --frobnicate's value; npm, not knowing the option, would run x. Unreadable.
    [['npx', ['--frobnicate', 'x', 'pkg@1.0.0']], ['001 ?']],
  ];
  for (const [[command, args], expected] of cases)
    assert.deepEqual(reported(command, args), expected, `${command} ${args.join(' ')}`);
});

test('fourth review: remaining branches', () => {
  const lock = (extra = {}) =>
    json({ lockfileVersion: 3, packages: { '': { name: 'app' }, 'node_modules/pkg': { version: '1.1.0' }, ...extra } });
  const cases = [
    // npm-shrinkwrap.json is read like package-lock.json.
    [['npx', ['-y', 'pkg@1.1.0']], { 'npm-shrinkwrap.json': lock() }, []],
    // The lockfile wins over a stale exact version in package.json.
    [
      ['npx', ['-y', 'pkg@1.0.0']],
      { 'package.json': json({ devDependencies: { pkg: '1.0.0' } }), 'package-lock.json': lock() },
      ['006 pkg@1.0.0'],
    ],
    [
      ['npx', ['-y', 'pkg@1.1.0']],
      { 'package.json': json({ devDependencies: { pkg: '1.0.0' } }), 'package-lock.json': lock() },
      [],
    ],
    // npx compares versions as ranges: v1.1.0 is 1.1.0.
    [['npx', ['-y', 'pkg@v1.1.0']], { 'package-lock.json': lock() }, []],
    // A link is found by its target's name.
    [
      ['npx', ['-y', 'real-name@0.1.0']],
      {
        'package-lock.json': lock({
          'node_modules/folder': { link: true, resolved: 'tools/x' },
          'tools/x': { name: 'real-name', version: '0.1.0' },
        }),
      },
      [],
    ],
    // Docker: joined letters with =, a metacharacter after cmd /c, and -lc.
    [['docker', ['run', '-ie=A=1', 'ghcr.io/o/mcp:1']], {}, ['006 ghcr.io/o/mcp:1']],
    [['bash', ['-lc', 'docker run -i ghcr.io/o/mcp']], {}, ['001 ghcr.io/o/mcp']],
    [['bash', ['-lc', 'exec -a mcp npx -y pkg@1.2.3']], {}, ['006 pkg@1.2.3']],
    [['bash', ['-c', 'exec -l -c npx -y pkg@1.2.3']], {}, ['006 pkg@1.2.3']],
    // uv tool install installs, it does not run a server.
    [['uv', ['tool', 'install', 'pkg']], {}, []],
  ];
  for (const [[command, args], files, expected] of cases)
    assert.deepEqual(
      reported(command, args, files),
      expected,
      `${command} ${args.join(' ')} ${Object.keys(files).join(',')}`,
    );
  const [shell] = findingsFor(scanFiles(server('cmd', ['/c', 'docker run -i ghcr.io/o/mcp:1 & calc'])), 'AGC-SUP-001');
  assert.match(shell.message, /shell line with more than one command/);
  // Packages from a file or handed to pip cannot be read.
  for (const args of [
    ['--with-requirements', 'reqs.txt', 'pkg@1.0.0'],
    ['--with-requirements=reqs.txt', 'pkg==1.0.0'],
  ]) {
    const found = scanFiles(server('uvx', args)).findings.filter(f => /AGC-SUP-00[16]/.test(f.ruleId));
    assert.deepEqual(
      found.map(f => f.ruleId),
      ['AGC-SUP-001'],
      args.join(' '),
    );
    assert.match(found[0].message, /with --with-requirements, which installs packages this check does not read/);
    assert.match(found[0].fix, /uvx --with pkg==1.2.3/);
  }
  const [pip] = findingsFor(scanFiles(server('pipx', ['run', '--pip-args', '-r reqs.txt', 'pkg==1.0'])), 'AGC-SUP-001');
  assert.match(pip.message, /with --pip-args, which installs packages/);
  // A deep v1 lockfile is read to a limit, without failing.
  let deep = { version: '1.0.0' };
  for (let i = 0; i < 100; i += 1) deep = { version: '1.0.0', dependencies: { [`d${i}`]: deep } };
  assert.ok(lockfileVersions({ dependencies: { top: deep } }).length <= 66);
});

test('bypass: enterprise owners are one actor, and the bypass finding has its own fingerprint', async () => {
  const owner = id => ({ actor_id: id, actor_type: 'EnterpriseOwner', bypass_mode: 'always' });
  const rules = await read({
    ...rulesOn([ownerRule(1), ownerRule(2)], {
      '/repos/acme/app/rulesets/1': ruleset(1, [owner(3)]),
      '/repos/acme/app/rulesets/2': ruleset(2, [owner(9)]),
    }),
    '/repos/acme/app/branches/main': [200, { protection: { enabled: false } }],
  });
  assert.equal(rules.codeOwnerBypass, 'possible');
  assert.match(rules.bypassWhy, /^enterprise owners may bypass/);
  // A baseline that holds the "not required" finding must not hide a later bypass finding.
  const gov = github => findingsFor(scanFiles(agentRepo, { github }), 'AGC-GOV-004')[0];
  const notRequired = gov({
    repo: 'acme/app',
    branch: 'main',
    codeOwnerReview: 'not-required',
    why: 'no rule requires it',
  });
  const bypass = gov(evidence('possible'));
  assert.notEqual(notRequired.fingerprint, bypass.fingerprint);
  assert.equal(
    bypass.fingerprint,
    createHash('sha256')
      .update(`AGC-GOV-004\0${bypass.agentId ?? ''}\0.github/CODEOWNERS\0code-owner-review:bypass`)
      .digest('hex')
      .slice(0, 20),
  );
});
