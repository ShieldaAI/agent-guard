// Variants from the third review round. Synthetic configs only.
import test from 'node:test';
import assert from 'node:assert/strict';
import { authority, shouldFail } from '@shieldaai/agent-guard-check';
import { findingsFor, mcp, ruleIds, scanFiles, settings } from './helpers.mjs';

const level = (agent, capability) => {
  const state = authority(agent)[capability];
  return state.value === 'no' ? 'no' : `${state.value}/${state.approval}`;
};
const pad = text => `${text}\n${' '.repeat(1_100_000)}\n`;
const agentic = (front, extra = {}) =>
  scanFiles({ '.github/workflows/w.md': `---\n${front}\n---\nDo the work.\n`, ...extra });
const wf = result => result.agents.find(agent => agent.id === 'agentic-workflow:.github/workflows/w.md');

test('an agent definition in Markdown padded past 1 MiB fails the default gate', () => {
  for (const [path, text] of [
    ['.claude/agents/helper.md', '---\nname: helper\ndescription: h\npermissionMode: bypassPermissions\n---\nGo.\n'],
    ['.github/workflows/triage.md', '---\non: issues\ntools:\n  bash: true\n---\nGo.\n'],
    ['.github/agents/a.agent.md', '---\ndescription: a\n---\nGo.\n'],
    ['.opencode/agent/x.md', '---\npermission:\n  bash: allow\n---\nGo.\n'],
  ]) {
    const result = scanFiles({ [path]: pad(text) });
    assert.equal(findingsFor(result, 'AGC-CFG-002')[0].severity, 'high', path);
    assert.equal(shouldFail(result.findings, 'high', 'high'), true, path);
  }
  assert.equal(findingsFor(scanFiles({ 'CLAUDE.md': pad('Notes.') }), 'AGC-CFG-002')[0].severity, 'medium');
});

test('gh-aw: any frontmatter with on: is a workflow, and its MCP servers are judged', () => {
  const result = agentic('on: issues\nmcp-servers:\n  evil:\n    command: node\n    args: [x.js]');
  assert.ok(wf(result));
  assert.ok(result.servers?.length ?? true);
  assert.equal(level(wf(result), 'privateData'), 'unknown/auto', 'an unknown server');
});

test('gh-aw: an import that cannot be read is unknown reach, whatever the engine', () => {
  for (const imports of [
    'imports:\n  - acme/shared/tools.md@0123abc',
    'imports:\n  - shared/missing.md',
    'imports:\n  - 7',
  ]) {
    const result = agentic(`on: workflow_dispatch\nengine: claude\n${imports}`);
    assert.equal(level(wf(result), 'exec'), 'unknown/auto', imports);
    assert.ok(
      findingsFor(result, 'AGC-CFG-001').some(f => /imports/.test(f.message)),
      imports,
    );
  }
  const big = agentic('on: workflow_dispatch\nengine: claude\nimports:\n  - shared/t.md', {
    '.github/workflows/shared/t.md': pad('---\ntools:\n  bash: true\n---'),
  });
  assert.equal(level(wf(big), 'exec'), 'unknown/auto', 'an import too large to read');
});

test('gh-aw: imports in object form are read, nested ones to a fixed depth', () => {
  const object = agentic('on: workflow_dispatch\nengine: claude\nimports:\n  - path: shared/t.md', {
    '.github/workflows/shared/t.md': '---\ntools:\n  bash: true\n---\n',
  });
  assert.equal(level(wf(object), 'exec'), 'yes/auto');
  const chain = {};
  for (let i = 1; i <= 5; i += 1)
    chain[`.github/workflows/shared/${i}.md`] = `---\nimports:\n  - shared/${i + 1}.md\n---\n`;
  chain['.github/workflows/shared/6.md'] = '---\ntools:\n  bash: true\n---\n';
  const deep = agentic('on: workflow_dispatch\nengine: claude\nimports:\n  - shared/1.md', chain);
  assert.equal(level(wf(deep), 'exec'), 'unknown/auto', 'beyond the depth limit is unknown, not no');
});

test('gh-aw: imported tool lists are joined, and an enabled tool is wider than a list', () => {
  const result = agentic('on: workflow_dispatch\nengine: claude\ntools:\n  bash: ["echo"]\nimports:\n  - shared/t.md', {
    '.github/workflows/shared/t.md': '---\ntools:\n  bash: [":*"]\n---\n',
  });
  assert.equal(level(wf(result), 'exec'), 'yes/auto');
});

test('gh-aw: secrets, tokens, unknown tools, read-write GitHub and custom jobs are counted', () => {
  const secret = agentic(
    'on: issues\nengine: claude\nenv:\n  PROD: ${{ secrets.PROD_DEPLOY_TOKEN }}\ntools:\n  bash: true\n  web-fetch:',
  );
  assert.equal(level(wf(secret), 'privateData'), 'yes/auto');
  const tool = agentic('on: workflow_dispatch\nengine: claude\ntools:\n  serena:');
  assert.equal(level(wf(tool), 'exec'), 'unknown/auto');
  assert.match(findingsFor(tool, 'AGC-CFG-001')[0].message, /tools = "serena"/);
  const rw = agentic(
    'on: workflow_dispatch\nengine: claude\ntools:\n  github:\n    read-only: false\n    github-token: ${{ secrets.ORG_PAT }}',
  );
  assert.equal(level(wf(rw), 'write'), 'yes/auto');
  assert.equal(level(wf(rw), 'egress'), 'yes/auto');
  const jobs = agentic('on: workflow_dispatch\nengine: claude\nsafe-outputs:\n  jobs:\n    deploy:\n      steps: []');
  assert.equal(level(wf(jobs), 'egress'), 'unknown/auto');
});

test('gh-aw: safe outputs are not a runtime check when threat detection is off', () => {
  const on = agentic('on: workflow_dispatch\nengine: claude\nsafe-outputs:\n  create-issue:');
  assert.equal(findingsFor(on, 'AGC-COV-001').length, 0);
  const off = agentic(
    'on: workflow_dispatch\nengine: claude\nsafe-outputs:\n  threat-detection: false\n  create-issue:',
  );
  assert.equal(findingsFor(off, 'AGC-COV-001').length, 1);
});

test('gh-aw: a container MCP server is judged by the policy and pinning rules', () => {
  const result = agentic(
    'on: workflow_dispatch\nengine: claude\nmcp-servers:\n  evil:\n    container: ghcr.io/attacker/evil:latest',
    {
      '.agc.yaml': 'policy:\n  allowed_mcp_servers: [github]\n',
    },
  );
  assert.ok(ruleIds(result).includes('AGC-POL-001'));
  assert.ok(ruleIds(result).includes('AGC-SUP-001'));
});

test('YAML merge keys in frontmatter are read', () => {
  const result = agentic('on: workflow_dispatch\nengine: claude\ndefaults: &d\n  bash: true\ntools:\n  <<: *d');
  assert.equal(level(wf(result), 'exec'), 'yes/auto');
});

const codex = withLines => `on: workflow_dispatch
permissions:
  contents: read
jobs:
  t:
    runs-on: ubuntu-latest
    steps:
      - uses: openai/codex-action@0123456789abcdef0123456789abcdef01234567
        with:
          prompt: x
${withLines}`;

test('codex-action: codex-args as a JSON array or a YAML list are read', () => {
  for (const args of [
    `          codex-args: '["--sandbox","danger-full-access"]'\n`,
    '          codex-args:\n            - --sandbox\n            - danger-full-access\n',
  ]) {
    const result = scanFiles({ '.github/workflows/t.yml': codex(args) });
    assert.ok(ruleIds(result).includes('AGC-PERM-001'), args);
    assert.equal(level(result.agents[0], 'egress'), 'yes/auto', args);
  }
});

test('codex: the wider sandbox wins when flags and inputs disagree', () => {
  const both = scanFiles({
    '.github/workflows/t.yml': codex('          sandbox: read-only\n          codex-args: --full-auto\n'),
  });
  assert.equal(level(both.agents[0], 'write'), 'yes/auto');
  const cli = scanFiles({
    '.github/workflows/t.yml':
      'on: workflow_dispatch\npermissions:\n  contents: read\njobs:\n  t:\n    runs-on: ubuntu-latest\n    steps:\n      - run: codex exec --sandbox read-only --full-auto "go"\n',
  });
  assert.equal(level(cli.agents[0], 'write'), 'yes/auto');
});

test('wide edit patterns and an allow-all rule can change the agent itself', () => {
  for (const rule of ['Edit(/**)', 'Edit(**/*.md)', 'Edit(**/*.json)', 'Edit(.*/**)', 'Edit(src/../**)', '*']) {
    const agent = scanFiles({ '.claude/settings.json': settings({ allow: [rule], deny: ['Edit'] }) }).agents[0];
    assert.equal(level(agent, 'selfModify') === 'no', false, rule);
  }
});

test('claude-code-action settings input and claude -p permission modes are read', () => {
  const action = settingsInput => `on: issue_comment
permissions:
  contents: read
jobs:
  c:
    runs-on: ubuntu-latest
    steps:
      - uses: anthropics/claude-code-action@0123456789abcdef0123456789abcdef01234567
        with:
          settings: '${settingsInput}'
`;
  const allowed = scanFiles({ '.github/workflows/c.yml': action('{"permissions":{"allow":["Bash","WebFetch"]}}') });
  assert.equal(level(allowed.agents[0], 'exec'), 'yes/auto');
  const bypass = scanFiles({
    '.github/workflows/c.yml': action('{"permissions":{"defaultMode":"bypassPermissions"}}'),
  });
  assert.ok(ruleIds(bypass).includes('AGC-PERM-001'));
  const run = mode =>
    scanFiles({
      '.github/workflows/c.yml': `on: workflow_dispatch\npermissions:\n  contents: read\njobs:\n  c:\n    runs-on: ubuntu-latest\n    steps:\n      - run: claude -p --permission-mode ${mode} "go"\n`,
    }).agents[0];
  assert.equal(level(run('acceptEdits'), 'write'), 'yes/auto');
  assert.equal(level(run('auto'), 'exec'), 'yes/auto');
});

test('a model endpoint override is reported', () => {
  const result = scanFiles({
    '.claude/settings.json': settings({}, { env: { ANTHROPIC_BASE_URL: 'https://proxy.example' } }),
  });
  assert.match(findingsFor(result, 'AGC-CFG-001')[0].message, /env\.ANTHROPIC_BASE_URL = "https:\/\/proxy\.example"/);
});

test('auto mode: no person approves, and its safety review is a runtime check', () => {
  const session = scanFiles({ '.claude/settings.json': settings({ defaultMode: 'auto' }) });
  assert.equal(level(session.agents[0], 'exec'), 'yes/auto');
  assert.equal(findingsFor(session, 'AGC-COV-001').length, 0);
  assert.ok(session.agents[0].mediators.some(mediator => mediator.kind === 'auto-mode'));
  const step = scanFiles({
    '.github/workflows/c.yml':
      'on: issues\npermissions:\n  issues: write\njobs:\n  c:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: anthropics/claude-code-action@0123456789abcdef0123456789abcdef01234567\n        with:\n          claude_args: --permission-mode auto --disallowedTools "WebFetch"\n',
  });
  assert.equal(findingsFor(step, 'AGC-PERM-001').length, 0, 'auto mode is not a bypass');
  assert.equal(findingsFor(step, 'AGC-COV-001').length, 0);
  assert.equal(level(step.agents[0], 'exec'), 'yes/auto');
  assert.ok(!step.agents[0].grants.some(grant => grant.tool === 'WebFetch'), 'disallowed tools stay out');
});

test('gh-aw: engine model keys and safe-output job secrets are not the agent’s; other engine secrets are', () => {
  const result = agentic(
    'on: workflow_dispatch\nengine:\n  id: claude\n  env:\n    ANTHROPIC_API_KEY: ${{ secrets.ZAI_API_KEY }}\nsafe-outputs:\n  threat-detection:\n    env:\n      K: ${{ secrets.DETECT_KEY }}\n  create-issue:',
  );
  assert.equal(level(wf(result), 'privateData'), 'no');
  const prod = agentic(
    'on: issues\nengine:\n  id: claude\n  env:\n    PROD_TOKEN: ${{ secrets.PROD_DEPLOY_TOKEN }}\ntools:\n  bash: true',
  );
  assert.equal(level(wf(prod), 'privateData'), 'yes/auto', 'the agent’s shell inherits the engine environment');
});
