import { test } from 'node:test';
import assert from 'node:assert/strict';
import { MemorySource, diffScans, fetchBranchRules, GitHubError, runCli, scan } from '@shieldaai/agent-guard-check';
import { findingsFor, settings } from './helpers.mjs';

const API = 'https://api.github.com';

/** A stand-in for GitHub: routes are `path -> [status, body]`; every request is recorded. */
function fakeGitHub(routes) {
  const requests = [];
  const fetch = async (url, init) => {
    requests.push({ url: String(url), headers: init?.headers ?? {} });
    const path = String(url).slice(API.length).replace(/\?.*$/, '');
    const [status, body, headers = {}] = routes[path] ?? [404, { message: 'Not Found' }];
    return new Response(JSON.stringify(body), { status, headers });
  };
  return { fetch, requests };
}

const ownerRule = (required = true) => ({
  type: 'pull_request',
  parameters: { require_code_owner_review: required, required_approving_review_count: 1 },
});

test('fetchBranchRules: an active ruleset that requires code owners', async () => {
  const github = fakeGitHub({
    '/repos/acme/app': [200, { default_branch: 'main' }],
    '/repos/acme/app/rules/branches/main': [200, [{ type: 'deletion' }, ownerRule()]],
  });
  const rules = await fetchBranchRules({ repo: 'acme/app', token: 't0k', fetch: github.fetch });
  assert.equal(rules.codeOwnerReview, 'required');
  assert.equal(rules.branch, 'main');
  assert.equal(github.requests[0].headers.authorization, 'Bearer t0k');
  assert.equal(github.requests.length, 2, 'stops once a ruleset decides');
});

test('fetchBranchRules: a pull-request rule without code owners, and no classic protection', async () => {
  const github = fakeGitHub({
    '/repos/acme/app/rules/branches/release/2': [200, [ownerRule(false)]],
    '/repos/acme/app/branches/release/2': [200, { protection: { enabled: false } }],
  });
  const rules = await fetchBranchRules({ repo: 'acme/app', branch: 'release/2', fetch: github.fetch });
  assert.equal(rules.codeOwnerReview, 'not-required');
  assert.ok(
    github.requests.every(request => !request.headers.authorization),
    'no token, no header',
  );
});

test('fetchBranchRules: classic protection is read when the token may, unknown when it may not', async () => {
  const base = {
    '/repos/acme/app/rules/branches/main': [200, []],
    '/repos/acme/app/branches/main': [200, { protection: { enabled: true } }],
  };
  const hidden = await fetchBranchRules({ repo: 'acme/app', branch: 'main', fetch: fakeGitHub(base).fetch });
  assert.equal(hidden.codeOwnerReview, 'unknown');
  assert.match(hidden.why, /admin access/);
  const on = fakeGitHub({
    ...base,
    '/repos/acme/app/branches/main/protection': [
      200,
      { required_pull_request_reviews: { require_code_owner_reviews: true } },
    ],
  });
  assert.equal(
    (await fetchBranchRules({ repo: 'acme/app', branch: 'main', fetch: on.fetch })).codeOwnerReview,
    'required',
  );
  const off = fakeGitHub({
    ...base,
    '/repos/acme/app/branches/main/protection': [200, { required_status_checks: {} }],
  });
  assert.equal(
    (await fetchBranchRules({ repo: 'acme/app', branch: 'main', fetch: off.fetch })).codeOwnerReview,
    'not-required',
  );
});

test('fetchBranchRules: follows pages of rules on the same API host only', async () => {
  const github = fakeGitHub({
    '/repos/acme/app/rules/branches/main': [
      200,
      [],
      { link: `<${API}/repos/acme/app/rules/branches/main2?page=2>; rel="next"` },
    ],
    '/repos/acme/app/rules/branches/main2': [200, [ownerRule()]],
  });
  assert.equal(
    (await fetchBranchRules({ repo: 'acme/app', branch: 'main', fetch: github.fetch })).codeOwnerReview,
    'required',
  );
  const elsewhere = fakeGitHub({
    '/repos/acme/app/rules/branches/main': [200, [], { link: '<https://evil.example/next>; rel="next"' }],
    '/repos/acme/app/branches/main': [200, { protection: { enabled: false } }],
  });
  await fetchBranchRules({ repo: 'acme/app', branch: 'main', token: 't0k', fetch: elsewhere.fetch });
  assert.ok(
    elsewhere.requests.every(request => request.url.startsWith(`${API}/`)),
    'the token never leaves GitHub',
  );
});

test('fetchBranchRules: refuses bad input and reports what GitHub refused', async () => {
  const github = fakeGitHub({});
  for (const repo of ['acme', 'acme/app/x', '../x', 'acme/..', 'a b/c'])
    await assert.rejects(fetchBranchRules({ repo, fetch: github.fetch }), GitHubError, repo);
  await assert.rejects(fetchBranchRules({ repo: 'acme/app', branch: 'feat*', fetch: github.fetch }), GitHubError);
  await assert.rejects(
    fetchBranchRules({ repo: 'acme/app', apiUrl: 'http://api.github.com', fetch: github.fetch }),
    /must be https/,
  );
  assert.equal(github.requests.length, 0, 'nothing is sent for bad input');
  await assert.rejects(
    fetchBranchRules({ repo: 'acme/app', branch: 'main', fetch: github.fetch }),
    /HTTP 404 \(not found, or the token cannot read it\)/,
  );
});

// --- AGC-GOV-004 ---------------------------------------------------------------------------------

const repoFiles = (allow = ['Bash(npm test:*)']) => ({
  '.claude/settings.json': settings({ allow }),
  CODEOWNERS: '# owners\n/.claude/ @acme/platform\n',
});
const evidence = codeOwnerReview => ({ repo: 'acme/app', branch: 'main', codeOwnerReview, why: 'test' });
const scanWith = (files, github) =>
  scan({ root: '/repo', source: new MemorySource(files), ...(github ? { github } : {}) });

test('AGC-GOV-004: owners named but not required, unknown, required, no evidence', () => {
  const [low] = findingsFor(scanWith(repoFiles(), evidence('not-required')), 'AGC-GOV-004');
  assert.equal(low.severity, 'low');
  assert.deepEqual(low.location, { file: 'CODEOWNERS', line: 2 });
  assert.match(low.message, /main does not require their approval/);
  assert.match(low.fix, /Require review from Code Owners/);
  const [info] = findingsFor(scanWith(repoFiles(), evidence('unknown')), 'AGC-GOV-004');
  assert.equal(info.severity, 'info');
  assert.equal(findingsFor(scanWith(repoFiles(), evidence('required')), 'AGC-GOV-004').length, 0);
  assert.equal(findingsFor(scanWith(repoFiles()), 'AGC-GOV-004').length, 0, 'files alone cannot tell');
});

test('AGC-GOV-004 stays out of the way of AGC-GOV-001 and repositories without agents', () => {
  const unowned = { '.claude/settings.json': settings({}), CODEOWNERS: '/docs/ @acme/docs\n' };
  const result = scanWith(unowned, evidence('not-required'));
  assert.equal(findingsFor(result, 'AGC-GOV-004').length, 0);
  assert.equal(findingsFor(result, 'AGC-GOV-001').length, 1);
  assert.equal(findingsFor(scanWith({ CODEOWNERS: '* @acme\n' }, evidence('not-required')), 'AGC-GOV-004').length, 0);
});

test('AGC-GOV-004 in a pull request: new on changes that widen an agent, quiet on the rest', () => {
  const github = evidence('not-required');
  const base = scanWith(repoFiles(), github);
  const unrelated = diffScans(base, scanWith({ ...repoFiles(), 'README.md': '# hi\n' }, github));
  assert.equal(findingsFor({ findings: unrelated.added }, 'AGC-GOV-004').length, 0);
  const widening = diffScans(base, scanWith(repoFiles(['Bash(npm test:*)', 'Bash(curl:*)']), github));
  assert.ok(widening.widened.length > 0);
  assert.equal(findingsFor({ findings: widening.added }, 'AGC-GOV-004').length, 1);
  const enforced = evidence('required');
  const covered = diffScans(scanWith(repoFiles(), enforced), scanWith(repoFiles(['Bash(curl:*)']), enforced));
  assert.equal(findingsFor({ findings: covered.added }, 'AGC-GOV-004').length, 0);
});

test('CLI --github-repo: reads branch rules, keeps the token out of messages, and never fails on GitHub', async () => {
  const { mkdtempSync, mkdirSync, writeFileSync, rmSync } = await import('node:fs');
  const { tmpdir } = await import('node:os');
  const { join } = await import('node:path');
  const dir = mkdtempSync(join(tmpdir(), 'agc-gh-'));
  try {
    mkdirSync(join(dir, '.claude'));
    for (const [path, text] of Object.entries(repoFiles())) writeFileSync(join(dir, path), text);
    const run = async (args, fetch, env = { GITHUB_TOKEN: 'secret-token-123' }) => {
      let stdout = '';
      let stderr = '';
      const code = await runCli([dir, '--format', 'json', '--fail-on', 'none', ...args], {
        stdout: text => (stdout += text),
        stderr: text => (stderr += text),
        cwd: dir,
        env,
        fetch,
      });
      return { code, stderr, json: stdout ? JSON.parse(stdout) : undefined };
    };
    const github = fakeGitHub({
      '/repos/acme/app/rules/branches/main': [200, []],
      '/repos/acme/app/branches/main': [200, { protection: { enabled: false } }],
    });
    const ok = await run(['--github-repo', 'acme/app', '--github-branch', 'main'], github.fetch);
    assert.equal(ok.code, 0);
    assert.equal(ok.json.modes.github.codeOwnerReview, 'not-required');
    assert.ok(ok.json.findings.some(finding => finding.ruleId === 'AGC-GOV-004'));
    assert.equal(github.requests[0].headers.authorization, 'Bearer secret-token-123');

    const refusing = async () =>
      new Response(JSON.stringify({ message: 'Bad credentials secret-token-123' }), { status: 401 });
    const down = await run(['--github-repo', 'acme/app'], refusing);
    assert.equal(down.code, 0, 'a GitHub failure is a warning');
    assert.match(down.stderr, /warning: could not read acme\/app: HTTP 401 \(the token was refused\)/);
    assert.ok(!down.stderr.includes('secret-token-123'), 'the token is masked');
    assert.equal(down.json.modes.github, undefined);

    assert.equal((await run(['--github-branch', 'main'], github.fetch)).code, 2);
    assert.equal((await run(['--github-repo', 'not a repo'], github.fetch)).code, 2);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('fetchBranchRules: answers unknown rather than not-required when it could not read everything', async () => {
  const many = {};
  for (let page = 0; page < 11; page++)
    many[`/repos/acme/app/rules/branches/p${page}`] = [
      200,
      [],
      { link: `<${API}/repos/acme/app/rules/branches/p${page + 1}>; rel="next"` },
    ];
  const pages = fakeGitHub({ ...many, '/repos/acme/app/branches/p0': [200, { protection: { enabled: false } }] });
  assert.equal(
    (await fetchBranchRules({ repo: 'acme/app', branch: 'p0', fetch: pages.fetch })).codeOwnerReview,
    'unknown',
  );
  const elsewhere = fakeGitHub({
    '/repos/acme/app/rules/branches/main': [200, [], { link: '<https://evil.example/next>; rel="next"' }],
  });
  assert.equal(
    (await fetchBranchRules({ repo: 'acme/app', branch: 'main', fetch: elsewhere.fetch })).codeOwnerReview,
    'unknown',
  );
  const silent = fakeGitHub({
    '/repos/acme/app/rules/branches/main': [200, []],
    '/repos/acme/app/branches/main': [200, { protected: true }],
  });
  assert.equal(
    (await fetchBranchRules({ repo: 'acme/app', branch: 'main', fetch: silent.fetch })).codeOwnerReview,
    'unknown',
    'protected, with no word on how',
  );
});

test('fetchBranchRules: branch names that would move the request, redirects, oversized answers', async () => {
  const github = fakeGitHub({});
  for (const branch of ['../../x', 'a/./b', 'a//b', '.hidden', 'a b', 'a~1'])
    await assert.rejects(
      fetchBranchRules({ repo: 'acme/app', branch, fetch: github.fetch }),
      /not a branch name/,
      branch,
    );
  assert.equal(github.requests.length, 0);
  const moved = async () => new Response(null, { status: 301, headers: { location: `${API}/repositories/1` } });
  await assert.rejects(fetchBranchRules({ repo: 'acme/app', branch: 'main', fetch: moved }), /renamed or moved/);
  const huge = async () => new Response('['.padEnd(5 * 1024 * 1024, ' '), { status: 200 });
  await assert.rejects(fetchBranchRules({ repo: 'acme/app', branch: 'main', fetch: huge }), /larger than 4 MiB/);
});

test('AGC-GOV-004 follows CODEOWNERS as GitHub does: the last matching line decides', () => {
  const github = evidence('not-required');
  const settingsFile = { '.claude/settings.json': settings({}) };
  const owned = text => findingsFor(scanWith({ ...settingsFile, CODEOWNERS: text }, github), 'AGC-GOV-004');
  assert.equal(owned('* @acme/all\n.claude/settings.json\n').length, 0, 'a line with no owner takes ownership away');
  assert.equal(owned('/.github/ @acme/ci\n').length, 0, 'a .github owner does not own .claude');
  assert.deepEqual(owned('/docs/ @acme/docs\n**/settings.json @acme/platform\n')[0]?.location.line, 2);
  assert.equal(owned('*.json @acme/platform\n').length, 1, 'an unanchored pattern matches at any depth');
  assert.equal(owned('/settings.json @acme/platform\n').length, 0, 'an anchored pattern does not');
});

test('AGC-GOV-004 in a pull request: not new for adding or moving CODEOWNERS; new for a new agent or record', () => {
  const github = evidence('not-required');
  const agent = { '.claude/settings.json': settings({ allow: ['Bash(npm test:*)'] }) };
  const owners = '/.claude/ @acme/platform\n';
  const added = diffScans(scanWith(agent, github), scanWith({ ...agent, CODEOWNERS: owners }, github));
  assert.equal(findingsFor({ findings: added.added }, 'AGC-GOV-004').length, 0, 'adding the owner');
  const moved = diffScans(
    scanWith({ ...agent, CODEOWNERS: owners }, github),
    scanWith({ ...agent, '.github/CODEOWNERS': owners }, github),
  );
  assert.equal(findingsFor({ findings: moved.added }, 'AGC-GOV-004').length, 0, 'moving CODEOWNERS');
  const base = scanWith({ CODEOWNERS: '* @acme/platform\n', 'README.md': '# x\n' }, github);
  const newAgent = diffScans(base, scanWith({ CODEOWNERS: '* @acme/platform\n', ...agent }, github));
  assert.ok(newAgent.newAgents.length > 0);
  assert.equal(findingsFor({ findings: newAgent.added }, 'AGC-GOV-004').length, 1, 'a new agent');
  const record = when =>
    `reviews:\n  - agent: .claude/settings.json\n    owner: '@acme/platform'\n    review_by: ${when}\n    capabilities: [exec]\n`;
  const files = { ...agent, CODEOWNERS: owners };
  const renewal = diffScans(
    scanWith({ ...files, '.agc-reviews.yaml': record('2099-01-01') }, github),
    scanWith({ ...files, '.agc-reviews.yaml': record('2099-06-01') }, github),
  );
  assert.ok(renewal.reviews.length > 0);
  assert.equal(findingsFor({ findings: renewal.added }, 'AGC-GOV-004').length, 1, 'an edited review record');
});

const ownerRuleIn = id => ({ ...ownerRule(), ruleset_id: id, ruleset_source_type: 'Repository' });
const admins = { actor_id: 5, actor_type: 'RepositoryRole', bypass_mode: 'always' };

test('fetchBranchRules: a ruleset that requires code owners and lets nobody bypass it', async () => {
  const github = fakeGitHub({
    '/repos/acme/app/rules/branches/main': [200, [ownerRuleIn(7)]],
    '/repos/acme/app/rulesets/7': [200, { id: 7, bypass_actors: [] }],
  });
  const rules = await fetchBranchRules({ repo: 'acme/app', branch: 'main', fetch: github.fetch });
  assert.equal(rules.codeOwnerReview, 'required');
  assert.equal(rules.codeOwnerBypass, 'none');
});

test('fetchBranchRules: a bypass list hidden from the token is unknown, not a bypass', async () => {
  const github = fakeGitHub({
    '/repos/acme/app/rules/branches/main': [200, [ownerRuleIn(7)]],
    '/repos/acme/app/rulesets/7': [200, { id: 7, current_user_can_bypass: 'never' }],
  });
  const rules = await fetchBranchRules({ repo: 'acme/app', branch: 'main', fetch: github.fetch });
  assert.equal(rules.codeOwnerReview, 'required');
  assert.equal(rules.codeOwnerBypass, 'unknown');
  assert.match(rules.bypassWhy, /admin access/);
  const failing = fakeGitHub({ '/repos/acme/app/rules/branches/main': [200, [ownerRuleIn(7)]] });
  const missing = await fetchBranchRules({ repo: 'acme/app', branch: 'main', fetch: failing.fetch });
  assert.equal(missing.codeOwnerReview, 'required', 'an unreadable ruleset never undoes the requirement');
  assert.equal(missing.codeOwnerBypass, 'unknown');
});

test('fetchBranchRules: admins on the bypass list, unless another rule lets nobody bypass', async () => {
  const routes = {
    '/repos/acme/app/rules/branches/main': [200, [ownerRuleIn(7)]],
    '/repos/acme/app/rulesets/7': [
      200,
      { id: 7, bypass_actors: [admins, { actor_id: 1, actor_type: 'Integration', bypass_mode: 'pull_request' }] },
    ],
    '/repos/acme/app/branches/main': [200, { protection: { enabled: false } }],
  };
  const open = await fetchBranchRules({ repo: 'acme/app', branch: 'main', fetch: fakeGitHub(routes).fetch });
  assert.equal(open.codeOwnerBypass, 'possible');
  assert.equal(open.bypassWhy, 'repository admins and a GitHub App may bypass the ruleset that requires it');

  // A second ruleset with no bypass list still binds everyone.
  const layered = fakeGitHub({
    ...routes,
    '/repos/acme/app/rules/branches/main': [200, [ownerRuleIn(7), ownerRuleIn(8)]],
    '/repos/acme/app/rulesets/8': [200, { id: 8, bypass_actors: [] }],
  });
  assert.equal(
    (await fetchBranchRules({ repo: 'acme/app', branch: 'main', fetch: layered.fetch })).codeOwnerBypass,
    'none',
  );

  // So does classic protection that requires code owners and includes admins.
  const classic = fakeGitHub({
    ...routes,
    '/repos/acme/app/branches/main': [200, { protection: { enabled: true } }],
    '/repos/acme/app/branches/main/protection': [
      200,
      { required_pull_request_reviews: { require_code_owner_reviews: true }, enforce_admins: { enabled: true } },
    ],
  });
  assert.equal(
    (await fetchBranchRules({ repo: 'acme/app', branch: 'main', fetch: classic.fetch })).codeOwnerBypass,
    'none',
  );
});

test('fetchBranchRules: classic protection that leaves out admins or allows bypass', async () => {
  const base = {
    '/repos/acme/app/rules/branches/main': [200, []],
    '/repos/acme/app/branches/main': [200, { protection: { enabled: true } }],
  };
  const withSettings = settingsBody =>
    fetchBranchRules({
      repo: 'acme/app',
      branch: 'main',
      fetch: fakeGitHub({ ...base, '/repos/acme/app/branches/main/protection': [200, settingsBody] }).fetch,
    });
  const noAdmins = await withSettings({
    required_pull_request_reviews: { require_code_owner_reviews: true },
    enforce_admins: { enabled: false },
  });
  assert.equal(noAdmins.codeOwnerBypass, 'possible');
  assert.match(noAdmins.bypassWhy, /^repository admins may bypass/);
  const allowances = await withSettings({
    required_pull_request_reviews: {
      require_code_owner_reviews: true,
      bypass_pull_request_allowances: { users: [{ login: 'release-bot' }], teams: [], apps: [] },
    },
    enforce_admins: { enabled: true },
  });
  assert.equal(allowances.bypassWhy, 'named users may bypass the branch protection rule that requires it');
  const strict = await withSettings({
    required_pull_request_reviews: { require_code_owner_reviews: true },
    enforce_admins: { enabled: true },
  });
  assert.equal(strict.codeOwnerBypass, 'none');
});

test('AGC-GOV-004: reports a bypass GitHub confirmed, and only that', () => {
  const files = { '.claude/settings.json': settings({}), '.github/CODEOWNERS': '/.claude/ @org/platform\n' };
  const github = state => ({
    repo: 'acme/app',
    branch: 'main',
    codeOwnerReview: 'required',
    why: 'an active ruleset on main requires review from code owners',
    codeOwnerBypass: state,
    bypassWhy: 'repository admins may bypass the ruleset that requires it',
  });
  const found = findingsFor(scanWith(files, github('possible')), 'AGC-GOV-004');
  assert.equal(found.length, 1);
  assert.equal(found[0].severity, 'low');
  assert.match(found[0].message, /repository admins may bypass/);
  for (const state of ['none', 'unknown', undefined])
    assert.equal(findingsFor(scanWith(files, github(state)), 'AGC-GOV-004').length, 0, state);
});
