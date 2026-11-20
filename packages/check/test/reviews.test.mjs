// Review records (.agc-reviews.yaml): owner, approved capabilities and a review_by date per agent.
import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { diffScans, formatJson, formatMarkdown, formatText, parseConfig, runCli } from '@shieldaai/agent-guard-check';
import { findingsFor, scanFiles, settings } from './helpers.mjs';

const NOW = Date.parse('2026-11-20T15:30:00Z');
const AGENT = { '.claude/settings.json': settings({ allow: ['Edit'] }) };

function record({
  agent = '.claude/settings.json',
  owner = '"@acme/platform"',
  date = '2027-03-01',
  caps = '[write, selfModify]',
} = {}) {
  return `  - agent: ${agent}\n    owner: ${owner}\n    review_by: ${date}\n    capabilities: ${caps}\n`;
}
const reviews = (...entries) => `reviews:\n${entries.join('')}`;

function run(files, { config, now = NOW, ...rest } = {}) {
  return scanFiles(files, { now, ...(config ? { config: parseConfig(config) } : {}), ...rest });
}
const rev = result => result.findings.filter(finding => finding.ruleId.startsWith('AGC-REV'));

test('a record that is current, approves what the agent does and has a code owner raises nothing', () => {
  const result = run({ ...AGENT, '.agc-reviews.yaml': reviews(record()), CODEOWNERS: '* @acme/platform\n' });
  assert.deepEqual(rev(result), []);
  assert.equal(result.reviews.length, 1);
  assert.deepEqual(result.reviews[0].agents, [result.agents[0].id]);
});

test('AGC-REV-001: a passed review date is high; due within 14 days is info; due today is not yet late', () => {
  const lapsed = findingsFor(
    run({ ...AGENT, '.agc-reviews.yaml': reviews(record({ date: '2026-11-19' })) }),
    'AGC-REV-001',
  );
  assert.equal(lapsed.length, 1);
  assert.equal(lapsed[0].severity, 'high');
  assert.match(lapsed[0].message, /due on 2026-11-19, 1 day ago \(owner @acme\/platform\)/);
  assert.match(lapsed[0].message, /fails every change until someone renews it/);
  assert.equal(lapsed[0].location.file, '.agc-reviews.yaml');
  assert.equal(lapsed[0].location.line, 2);

  const today = findingsFor(
    run({ ...AGENT, '.agc-reviews.yaml': reviews(record({ date: '2026-11-20' })) }),
    'AGC-REV-001',
  );
  assert.deepEqual(
    today.map(f => [f.severity, /today/.test(f.message)]),
    [['info', true]],
  );
  const soon = findingsFor(
    run({ ...AGENT, '.agc-reviews.yaml': reviews(record({ date: '2026-12-04' })) }),
    'AGC-REV-001',
  );
  assert.deepEqual(
    soon.map(f => f.severity),
    ['info'],
  );
  const later = findingsFor(
    run({ ...AGENT, '.agc-reviews.yaml': reviews(record({ date: '2026-12-05' })) }),
    'AGC-REV-001',
  );
  assert.deepEqual(later, []);
});

test('AGC-REV-002 runs only with policy.require_reviews and accepts a record by file, ID or name', () => {
  const files = {
    ...AGENT,
    '.claude/agents/triage.md': '---\nname: triage\ndescription: Sorts issues\ntools: Read\n---\nSort.\n',
  };
  assert.deepEqual(findingsFor(run(files), 'AGC-REV-002'), [], 'off by default');
  const config = 'policy:\n  require_reviews: true\n';
  const missing = findingsFor(run(files, { config }), 'AGC-REV-002');
  assert.equal(missing.length, 2);
  assert.ok(missing.every(f => f.severity === 'high'));

  const ids = run(files).agents.map(agent => agent.id);
  const subagent = run(files).agents.find(agent => agent.location.file === '.claude/agents/triage.md');
  for (const name of [subagent.location.file, subagent.id, subagent.name]) {
    const covered = run(
      { ...files, '.agc-reviews.yaml': reviews(record(), record({ agent: JSON.stringify(name), caps: '[]' })) },
      { config },
    );
    assert.deepEqual(findingsFor(covered, 'AGC-REV-002'), [], `covered by ${name}`);
  }
  assert.equal(ids.length, 2);
});

test('AGC-REV-003: access without asking beyond what the review approved; prompts do not count', () => {
  const narrow = run({ ...AGENT, '.agc-reviews.yaml': reviews(record({ caps: '[write]' })) });
  const found = findingsFor(narrow, 'AGC-REV-003');
  assert.equal(found.length, 1);
  assert.equal(found[0].severity, 'high');
  assert.match(found[0].message, /changes itself/);

  // WebFetch behind the default prompt is reviewed at every call: not part of the record.
  const asked = run({
    '.claude/settings.json': settings({ allow: ['Edit'], ask: ['WebFetch'] }),
    '.agc-reviews.yaml': reviews(record()),
  });
  assert.deepEqual(findingsFor(asked, 'AGC-REV-003'), []);

  // A change that adds Bash without asking must also change the record.
  const widened = run({
    '.claude/settings.json': settings({ allow: ['Edit', 'Bash'] }),
    '.agc-reviews.yaml': reviews(record()),
  });
  const extra = findingsFor(widened, 'AGC-REV-003');
  assert.equal(extra.length, 1);
  assert.match(extra[0].message, /runs code/);
  assert.match(extra[0].fix, /exec/);
});

test('AGC-REV-003 is medium when the extra capability is only possible', () => {
  const result = run({
    // Edited code runs through npm test without asking: it may send data out.
    '.claude/settings.json': settings({ allow: ['Bash(npm test)', 'Edit'] }),
    '.agc-reviews.yaml': reviews(record({ caps: '[exec, write, selfModify]' })),
  });
  const found = findingsFor(result, 'AGC-REV-003');
  assert.equal(found.length, 1);
  assert.equal(found[0].severity, 'medium');
  assert.match(found[0].message, /sends data out \(maybe\)/);
});

test('a review change marks what is only possible and what the record does not approve', () => {
  const files = caps => ({
    '.claude/settings.json': settings({ allow: ['Bash(npm test)', 'Edit'] }),
    '.agc-reviews.yaml': reviews(record({ caps, date: '2027-05-01' })),
  });
  const base = run(files('[exec, write, selfModify, egress]'));
  const head = run(files('[selfModify, write, exec]'));
  const diff = diffScans(base, head);
  assert.deepEqual(diff.reviews[0].maybe, ['egress']);
  assert.match(
    formatText(head, diff),
    /approves write, exec, selfModify \(was write, exec, egress, selfModify\); can do now without asking: write, exec, egress \(maybe\) \(not approved\), selfModify/,
  );
  const md = formatMarkdown(head, diff);
  assert.match(md, /\| write, exec, \*\*egress \(maybe\)\*\* \(not approved\), selfModify \|/);
  assert.equal(JSON.parse(formatJson(head, diff)).diff.reviews[0].maybe[0], 'egress');
});

test('AGC-REV-004: a review date past policy.max_review_days (default 365)', () => {
  const far = findingsFor(
    run({ ...AGENT, '.agc-reviews.yaml': reviews(record({ date: '2027-11-21' })) }),
    'AGC-REV-004',
  );
  assert.equal(far.length, 1);
  assert.match(far[0].message, /366 days away; the limit is 365 days/);
  assert.deepEqual(
    findingsFor(run({ ...AGENT, '.agc-reviews.yaml': reviews(record({ date: '2027-11-20' })) }), 'AGC-REV-004'),
    [],
  );
  const config = 'policy:\n  max_review_days: 90\n';
  assert.equal(
    findingsFor(
      run({ ...AGENT, '.agc-reviews.yaml': reviews(record({ date: '2027-03-01' })) }, { config }),
      'AGC-REV-004',
    ).length,
    1,
  );
});

test('AGC-REV-005: a record that names no agent', () => {
  const result = run({ ...AGENT, '.agc-reviews.yaml': reviews(record(), record({ agent: '.claude/old.json' })) });
  const found = findingsFor(result, 'AGC-REV-005');
  assert.equal(found.length, 1);
  assert.match(found[0].message, /\.claude\/old\.json matches no agent/);
  assert.doesNotMatch(found[0].message, /Did you mean/);
});

test('AGC-REV-005 suggests the file when the entry names a subagent by its front-matter name', () => {
  const result = run({
    ...AGENT,
    '.claude/agents/reviewer.md': '---\nname: reviewer\ndescription: Reviews\ntools: Read\n---\nReview.\n',
    '.agc-reviews.yaml': reviews(record(), record({ agent: 'reviewer', caps: '[]' })),
  });
  const found = findingsFor(result, 'AGC-REV-005');
  assert.equal(found.length, 1);
  assert.match(found[0].message, /Did you mean \.claude\/agents\/reviewer\.md\?/);
  assert.match(found[0].fix, /Set agent to \.claude\/agents\/reviewer\.md/);
});

test('AGC-REV-006: owner absent from CODEOWNERS; case-insensitive; silent without CODEOWNERS', () => {
  const file = { ...AGENT, '.agc-reviews.yaml': reviews(record()) };
  assert.deepEqual(findingsFor(run(file), 'AGC-REV-006'), []);
  assert.equal(findingsFor(run({ ...file, CODEOWNERS: '* @someone-else\n' }), 'AGC-REV-006')[0].severity, 'low');
  assert.deepEqual(
    findingsFor(run({ ...file, '.github/CODEOWNERS': '/.claude/ @ACME/Platform\n' }), 'AGC-REV-006'),
    [],
  );
  assert.equal(
    findingsFor(run({ ...file, CODEOWNERS: '# @acme/platform left\n* @someone-else\n' }), 'AGC-REV-006').length,
    1,
    'a comment does not count',
  );
});

test('AGC-REV-007: records that cannot be read are findings, never guesses', () => {
  const cases = [
    [record({ owner: '""' }), /owner is required/],
    [record({ date: '2027-02-30' }), /review_by/],
    [record({ date: '"next spring"' }), /review_by/],
    [record({ caps: '[write, admin]' }), /unknown capability "admin"/],
    [record({ caps: 'write' }), /capabilities is required/],
    [`${record()}    reviewer: someone\n`, /unknown key "reviewer"/],
    [record() + record(), /already names this agent/],
  ];
  for (const [entry, pattern] of cases) {
    const result = run({ ...AGENT, '.agc-reviews.yaml': reviews(entry) });
    const found = findingsFor(result, 'AGC-REV-007');
    assert.equal(found.length, 1, entry);
    assert.equal(found[0].severity, 'high');
    assert.match(found[0].message, pattern);
  }
  for (const text of ['reviews: [unclosed', 'reviews: 3\n', 'review:\n  - agent: x\n', '- agent: x\n']) {
    const found = findingsFor(run({ ...AGENT, '.agc-reviews.yaml': text }), 'AGC-REV-007');
    assert.equal(found.length, 1, text);
  }
  assert.deepEqual(rev(run({ ...AGENT, '.agc-reviews.yaml': '' })), [], 'an empty file is no records');
});

test('a quoted date and a YAML timestamp both read as the same day', () => {
  for (const date of ['"2026-11-01"', '2026-11-01', "'2026-11-01'"])
    assert.equal(
      findingsFor(run({ ...AGENT, '.agc-reviews.yaml': reviews(record({ date })) }), 'AGC-REV-001').length,
      1,
    );
});

test('an inline agc-ignore comment cannot silence a passed review date, before or after it passes', () => {
  const ignored = `reviews:\n  # agc-ignore AGC-REV-001: renewing next sprint\n${record({ date: '2026-11-01' }).replace('review_by: 2026-11-01', 'review_by: 2026-11-01 # agc-ignore AGC-REV-001: later')}`;
  const head = run({ ...AGENT, '.agc-reviews.yaml': ignored });
  assert.equal(findingsFor(head, 'AGC-REV-001').length, 1);
  assert.deepEqual(
    head.suppressed.filter(item => item.finding.ruleId === 'AGC-REV-001'),
    [],
  );
  const base = run({ ...AGENT, '.agc-reviews.yaml': reviews(record({ date: '2026-11-01' })) });
  const diff = diffScans(base, head);
  assert.deepEqual(
    diff.added.map(f => f.ruleId),
    ['AGC-REV-001'],
  );
  assert.deepEqual(diff.resolved, []);
  // Written while the date was ahead, the comment does nothing once it passes either.
  const later = run(
    { ...AGENT, '.agc-reviews.yaml': ignored.replace(/2026-11-01/g, '2026-11-30') },
    {
      now: Date.parse('2026-12-05T00:00:00Z'),
    },
  );
  assert.equal(findingsFor(later, 'AGC-REV-001')[0].severity, 'high');
});

test('a review due soon is a note, and it does not count as new in every pull request', () => {
  const files = { ...AGENT, '.agc-reviews.yaml': reviews(record({ date: '2026-11-25' })) };
  const diff = diffScans(run(files), run(files));
  assert.deepEqual(diff.added, []);
});

test('moving an agent while widening it fails: the record no longer matches, at high', () => {
  const head = run({
    '.claude/agents/triage-bot.md': '---\nname: triage\ndescription: d\ntools: Read, Bash\n---\nx\n',
    '.agc-reviews.yaml': reviews(record({ agent: '.claude/agents/triage.md', caps: '[]' })),
  });
  const found = findingsFor(head, 'AGC-REV-005');
  assert.equal(found.length, 1);
  assert.equal(found[0].severity, 'high');
  assert.match(found[0].message, /no longer checked against it/);
});

test('a name shared by several agents covers none of them, so a copied name borrows no review', () => {
  const sub = tools => `---\nname: deployer\ndescription: d\ntools: ${tools}\n---\nx\n`;
  const files = {
    '.claude/agents/deployer.md': sub('Read'),
    '.claude/agents/copy.md': sub('Read, Bash'),
    '.agc-reviews.yaml': reviews(record({ agent: 'Subagent deployer', caps: '[]' })),
  };
  const result = run(files, { config: 'policy:\n  require_reviews: true\n' });
  assert.deepEqual(result.reviews[0].agents, []);
  assert.deepEqual(
    findingsFor(result, 'AGC-REV-002')
      .map(f => f.agentId)
      .filter(id => id.startsWith('subagent:'))
      .sort(),
    ['subagent:.claude/agents/copy.md', 'subagent:.claude/agents/deployer.md'],
  );
  const orphan = findingsFor(result, 'AGC-REV-005');
  assert.equal(orphan.length, 1);
  assert.match(orphan[0].message, /names agents in 2 files by the same name, so it covers none of them/);
  // With one agent of that name, the name works.
  delete files['.claude/agents/copy.md'];
  assert.equal(run(files).reviews[0].agents.length, 1);
});

test('a name the scanner built for agents of one file still covers them all', () => {
  const step = `      - uses: anthropics/claude-code-action@0123456789abcdef0123456789abcdef01234567\n        with:\n          prompt: Label this issue\n`;
  const workflow = `name: triage\non: issues\npermissions:\n  contents: read\njobs:\n  triage:\n    runs-on: ubuntu-latest\n    timeout-minutes: 10\n    steps:\n${step}${step}`;
  const result = run({
    '.github/workflows/triage.yml': workflow,
    '.agc-reviews.yaml': reviews(record({ agent: '"Workflow triage.yml › triage"', caps: '[untrustedInput]' })),
  });
  const workflows = result.agents.filter(agent => agent.kind === 'workflow');
  assert.equal(workflows.length, 2);
  assert.equal(new Set(workflows.map(agent => agent.name)).size, 1);
  assert.deepEqual(result.reviews[0].agents.sort(), workflows.map(agent => agent.id).sort());
  assert.deepEqual(findingsFor(result, 'AGC-REV-005'), []);
});

test('a YAML 1.1 timestamp counts only when written as the day itself', () => {
  const v11 = entry => `%YAML 1.1\n---\n${reviews(entry)}`;
  for (const date of ['2026-11-19T00:00:00-24:00', '2026-11-19T24:00:00Z', '2026-11-17T96:00:00Z', '2026-10-62']) {
    const result = run({ ...AGENT, '.agc-reviews.yaml': v11(record({ date })) });
    assert.equal(findingsFor(result, 'AGC-REV-007').length, 1, date);
    assert.deepEqual(result.reviews, [], date);
  }
  const plain = run({ ...AGENT, '.agc-reviews.yaml': v11(record({ date: '2026-11-19' })) });
  assert.equal(findingsFor(plain, 'AGC-REV-001')[0].severity, 'high');
});

test('an unreadable record cannot be silenced inline, so breaking a lapsed entry does not hide it', () => {
  const broken = `reviews:\n  # agc-ignore AGC-REV-007: tidying later\n${record({ date: '"soon"' })}`;
  const result = run({ ...AGENT, '.agc-reviews.yaml': broken });
  assert.equal(findingsFor(result, 'AGC-REV-007').length, 1);
  assert.deepEqual(result.suppressed, []);
});

test('a removed record is described the same way in text and Markdown', () => {
  const base = run({ ...AGENT, '.agc-reviews.yaml': reviews(record()) });
  const head = run(AGENT);
  const diff = diffScans(base, head);
  assert.match(formatText(head, diff), /\(removed\).*can do now without asking: write, selfModify$/m);
  assert.match(formatMarkdown(head, diff), /\| write, selfModify \|$/m);
  assert.doesNotMatch(formatMarkdown(head, diff), /not approved/);
});

test('each record is located at its own entry, even when its name appears earlier in the file', () => {
  const text = reviews(
    record({ agent: '.claude/agents/triage.md', owner: '"@acme/triage-team"' }),
    record({ agent: 'triage', date: '2026-11-01' }),
  );
  const result = run({ ...AGENT, '.agc-reviews.yaml': text });
  const lapsed = findingsFor(result, 'AGC-REV-001');
  assert.equal(lapsed.length, 1);
  assert.equal(lapsed[0].location.line, 6);
  assert.deepEqual(
    result.reviews.map(item => item.location.line),
    [2, 6],
  );
});

test('a timestamp with a time of day or an offset is not a review date', () => {
  for (const date of ['!!timestamp 2027-01-01T23:00:00-05:00', '!!timestamp 2027-01-01T12:00:00Z']) {
    const found = findingsFor(run({ ...AGENT, '.agc-reviews.yaml': reviews(record({ date })) }), 'AGC-REV-007');
    assert.equal(found.length, 1, date);
  }
  const midnight = run({ ...AGENT, '.agc-reviews.yaml': reviews(record({ date: '!!timestamp 2027-01-01' })) });
  assert.equal(midnight.reviews[0].reviewBy, '2027-01-01');
});

test('a baseline cannot silence a passed review date, but still silences other findings', () => {
  const files = { ...AGENT, '.agc-reviews.yaml': reviews(record({ date: '2026-11-01', caps: '[]' })) };
  const first = run(files);
  const baseline = new Set(first.findings.map(f => f.fingerprint));
  const again = run(files, { baseline });
  assert.deepEqual(
    again.findings.map(f => f.ruleId),
    ['AGC-REV-001'],
  );
  assert.ok(again.suppressed.some(item => item.finding.ruleId === 'AGC-REV-003'));
});

test('in a pull request a passed review date counts as new, so every change fails until it is renewed', () => {
  const files = { ...AGENT, '.agc-reviews.yaml': reviews(record({ date: '2026-11-01' })) };
  const base = run(files);
  const unrelated = diffScans(base, run({ ...files, 'README.md': 'docs' }));
  assert.deepEqual(
    unrelated.added.map(f => f.ruleId),
    ['AGC-REV-001'],
  );
  assert.deepEqual(unrelated.reviews, []);
});

test('a renewal shows what it approves and what the agent can do now, not just the date', () => {
  const base = run({ ...AGENT, '.agc-reviews.yaml': reviews(record({ date: '2026-11-01' })) });
  const head = run({ ...AGENT, '.agc-reviews.yaml': reviews(record({ date: '2027-05-01' })) });
  const diff = diffScans(base, head);
  assert.deepEqual(diff.added, []);
  assert.equal(diff.reviews.length, 1);
  assert.deepEqual(diff.reviews[0].current, ['write', 'selfModify']);
  const text = formatText(head, diff);
  assert.match(
    text,
    /\.claude\/settings\.json \(changed\): review by 2026-11-01 → 2027-05-01; owner @acme\/platform; approves write, selfModify \(unchanged\); can do now without asking: write, selfModify/,
  );
  assert.match(text, /review: owner @acme\/platform, due 2027-05-01, approved write, selfModify/);
  const md = formatMarkdown(head, diff);
  assert.match(md, /1 review record\(s\) changed/);
  assert.match(md, /\| Review record \| Change \| Review by \| Owner \| Approves \| Can do now without asking \|/);
  assert.ok(md.includes('@⁠acme/platform'), 'owners are not turned into mentions');
  const json = JSON.parse(formatJson(head, diff));
  assert.deepEqual(json.diff.reviews[0].before.reviewBy, '2026-11-01');
  assert.deepEqual(json.diff.reviews[0].after.capabilities, ['write', 'selfModify']);
  assert.equal(json.reviews[0].owner, '@acme/platform');
});

test('a change that widens access and approves it in the record shows both', () => {
  const base = run({ ...AGENT, '.agc-reviews.yaml': reviews(record()) });
  const head = run({
    '.claude/settings.json': settings({ allow: ['Edit', 'Bash'] }),
    '.agc-reviews.yaml': reviews(record({ caps: '[write, selfModify, exec, egress, untrustedInput, privateData]' })),
  });
  const diff = diffScans(base, head);
  assert.ok(diff.widened.some(change => change.capability === 'exec'));
  assert.match(formatText(head, diff), /approves .*exec.* \(was write, selfModify\)/);
});

test('removing a record is listed, and with require_reviews it fails as a missing record', () => {
  const config = 'policy:\n  require_reviews: true\n';
  const base = run({ ...AGENT, '.agc-reviews.yaml': reviews(record()) }, { config });
  const head = run({ ...AGENT }, { config });
  const diff = diffScans(base, head);
  assert.equal(diff.reviews.length, 1);
  assert.equal(diff.reviews[0].after, undefined);
  assert.match(formatText(head, diff), /\(removed\): review by 2027-03-01 → removed/);
  assert.deepEqual(
    diff.added.map(f => f.ruleId),
    ['AGC-REV-002'],
  );
});

test('.agc.yaml validates the review policy', () => {
  assert.equal(parseConfig('policy:\n  require_reviews: true\n').policy.requireReviews, true);
  assert.equal(parseConfig('').policy.maxReviewDays, 365);
  assert.throws(() => parseConfig('policy:\n  require_reviews: yes please\n'), /require_reviews/);
  assert.throws(() => parseConfig('policy:\n  max_review_days: 0\n'), /max_review_days/);
  assert.throws(() => parseConfig('policy:\n  max_review_days: 30.5\n'), /max_review_days/);
});

test('settings outside the repository are not shipped agents and need no record', () => {
  const result = run(
    { ...AGENT, '.agc-reviews.yaml': reviews(record()) },
    {
      config: 'policy:\n  require_reviews: true\n',
      userFiles: [{ path: '~/.claude/settings.json', text: settings({ allow: ['Bash'] }) }],
      root: '/repo',
    },
  );
  assert.deepEqual(findingsFor(result, 'AGC-REV-002'), []);
});

// --- CLI: --base reads the review file from the change, the review policy from the base ---

function day(offset) {
  return new Date(Date.now() + offset * 86_400_000).toISOString().slice(0, 10);
}

function git(dir, ...args) {
  const result = spawnSync(
    'git',
    ['-C', dir, '-c', 'user.name=t', '-c', 'user.email=t@example.com', '-c', 'commit.gpgsign=false', ...args],
    { encoding: 'utf8' },
  );
  assert.equal(result.status, 0, result.stderr);
}

function write(dir, files) {
  for (const [path, text] of Object.entries(files)) {
    mkdirSync(join(dir, path, '..'), { recursive: true });
    writeFileSync(join(dir, path), text);
  }
}

async function cli(args, cwd) {
  let stdout = '';
  const code = await runCli(args, { stdout: text => (stdout += text), stderr: () => {}, cwd, env: {} });
  return { code, stdout };
}

test('CLI --base: a lapsed review fails an unrelated change; the renewal passes; the base sets the limit', async t => {
  const dir = mkdtempSync(join(tmpdir(), 'agc-reviews-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  write(dir, {
    ...AGENT,
    '.agc.yaml': 'policy:\n  max_review_days: 200\n',
    '.agc-reviews.yaml': reviews(record({ date: day(-3) })),
  });
  git(dir, 'init', '-q', '-b', 'main');
  git(dir, 'add', '.');
  git(dir, 'commit', '-q', '-m', 'base');

  write(dir, { 'README.md': 'unrelated\n' });
  const unrelated = await cli(['.', '--base', 'main'], dir);
  assert.equal(unrelated.code, 1, unrelated.stdout);
  assert.match(unrelated.stdout, /AGC-REV-001/);

  write(dir, { '.agc-reviews.yaml': reviews(record({ date: day(150) })) });
  const renewal = await cli(['.', '--base', 'main'], dir);
  assert.equal(renewal.code, 0, renewal.stdout);
  assert.match(renewal.stdout, /Review records changed by this change:/);

  // The change cannot raise its own limit: .agc.yaml comes from the base.
  write(dir, {
    '.agc.yaml': 'policy:\n  max_review_days: 3650\n',
    '.agc-reviews.yaml': reviews(record({ date: day(900) })),
  });
  const snooze = await cli(['.', '--base', 'main'], dir);
  assert.equal(snooze.code, 1, snooze.stdout);
  assert.match(snooze.stdout, /AGC-REV-004/);
});
