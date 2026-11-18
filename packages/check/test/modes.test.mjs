// Permission modes and settings the scanner does not model. Synthetic configs only.
import test from 'node:test';
import assert from 'node:assert/strict';
import { authority, shouldFail } from '@shieldaai/agent-guard-check';
import { findingsFor, scanFiles, settings } from './helpers.mjs';

const level = (agent, capability) => {
  const state = authority(agent)[capability];
  return state.value === 'no' ? 'no' : `${state.value}/${state.approval}`;
};
const main = result => result.agents.find(agent => agent.kind === 'claude-code');

test('defaultMode auto: a classifier, not a person, approves each call', () => {
  const result = scanFiles({ '.claude/settings.json': settings({ defaultMode: 'auto' }) });
  assert.equal(level(main(result), 'egress'), 'yes/auto');
  assert.equal(level(main(result), 'exec'), 'yes/auto');
  assert.ok(main(result).grants.some(grant => grant.via === 'Bash (defaultMode: auto)'));
  assert.equal(findingsFor(result, 'AGC-CFG-001').length, 0, 'auto is a known mode');
});

test('defaultMode dontAsk: only allowed tools run, the rest are denied', () => {
  const result = scanFiles({
    '.claude/settings.json': settings({ defaultMode: 'dontAsk', allow: ['Bash(npm test:*)'] }),
  });
  assert.equal(level(main(result), 'egress'), 'no');
  assert.equal(level(main(result), 'untrustedInput'), 'no');
  assert.equal(level(main(result), 'exec'), 'yes/auto');
});

test('defaultMode acceptEdits also runs mkdir, touch, mv and cp without asking', () => {
  const result = scanFiles({ '.claude/settings.json': settings({ defaultMode: 'acceptEdits' }) });
  const writes = authority(main(result))
    .write.grants.filter(grant => grant.approval === 'auto')
    .map(g => g.via);
  assert.ok(writes.includes('Edit'));
  assert.ok(writes.includes('Bash(mkdir, touch, mv, cp)'));
  assert.equal(level(main(result), 'exec'), 'yes/ask', 'other commands still ask');
});

test('manual and plan are read like default', () => {
  const plain = scanFiles({ '.claude/settings.json': settings({}) });
  for (const mode of ['manual', 'plan', 'default']) {
    const result = scanFiles({ '.claude/settings.json': settings({ defaultMode: mode }) });
    for (const capability of ['egress', 'exec', 'write', 'untrustedInput'])
      assert.equal(level(main(result), capability), level(main(plain), capability), `${mode} ${capability}`);
    assert.equal(findingsFor(result, 'AGC-CFG-001').length, 0, mode);
  }
});

test('an unknown mode is assumed to run everything, with the reach unknown, and is reported', () => {
  const result = scanFiles({ '.claude/settings.json': settings({ defaultMode: 'turbo' }) });
  assert.equal(level(main(result), 'egress'), 'unknown/auto');
  const [finding] = findingsFor(result, 'AGC-CFG-001');
  assert.ok(finding);
  assert.equal(finding.severity, 'info');
  assert.equal(finding.confidence, 'low');
  assert.match(
    finding.message,
    /defaultMode = "turbo" is not modelled; the scan assumed every tool runs without asking/,
  );
  assert.equal(finding.location.line, 3);
  assert.equal(shouldFail([finding], 'info', 'high'), false, 'a note never fails a run at the default confidence');
});

test('a subagent in auto mode is reported, and its calls need no person', () => {
  const result = scanFiles({
    '.claude/agents/runner.md': '---\nname: runner\ndescription: runs\npermissionMode: auto\n---\nGo.\n',
  });
  const sub = result.agents.find(agent => agent.kind === 'subagent');
  assert.equal(level(sub, 'egress'), 'yes/auto');
  const [finding] = findingsFor(result, 'AGC-PERM-006');
  assert.equal(finding.severity, 'medium');
  assert.match(finding.message, /a classifier, not a person, approves/);
  const parentAuto = scanFiles({
    '.claude/settings.json': settings({ defaultMode: 'auto' }),
    '.claude/agents/runner.md': '---\nname: runner\ndescription: runs\npermissionMode: auto\n---\nGo.\n',
  });
  assert.equal(findingsFor(parentAuto, 'AGC-PERM-006').length, 0, 'not broader than an auto parent');
});

test('a subagent in acceptEdits mode is still a low finding', () => {
  const result = scanFiles({
    '.claude/agents/editor.md': '---\nname: editor\ndescription: edits\npermissionMode: acceptEdits\n---\nGo.\n',
  });
  assert.equal(findingsFor(result, 'AGC-PERM-006')[0].severity, 'low');
});

test('a subagent with an unknown mode is reported and judged as running everything', () => {
  const result = scanFiles({
    '.claude/agents/x.md': '---\nname: x\ndescription: x\npermissionMode: yolo\n---\nGo.\n',
  });
  const sub = result.agents.find(agent => agent.kind === 'subagent');
  assert.equal(level(sub, 'egress'), 'unknown/auto');
  assert.match(findingsFor(result, 'AGC-CFG-001')[0].message, /Subagent x: permissionMode = "yolo"/);
});

test('Codex: an unknown sandbox is judged as no sandbox, and an unknown policy is reported', () => {
  const result = scanFiles({ '.codex/config.toml': 'sandbox_mode = "container"\napproval_policy = "sometimes"\n' });
  const codex = result.agents.find(agent => agent.kind === 'codex');
  assert.equal(level(codex, 'exec'), 'unknown/auto');
  assert.ok(
    codex.grants.some(
      grant => grant.capability === 'egress' && grant.approval === 'auto' && grant.certainty === 'unknown',
    ),
    'network reach without asking is unknown, not ruled out',
  );
  const notes = findingsFor(result, 'AGC-CFG-001').map(finding => finding.message);
  assert.ok(notes.some(text => text.includes('sandbox_mode = "container"')));
  assert.ok(notes.some(text => text.includes('approval_policy = "sometimes"')));
  const known = scanFiles({ '.codex/config.toml': 'sandbox_mode = "read-only"\napproval_policy = "on-request"\n' });
  assert.equal(findingsFor(known, 'AGC-CFG-001').length, 0);
});

test('Gemini CLI: an unknown approval mode runs built-in tools without asking, reach unknown', () => {
  const result = scanFiles({ '.gemini/settings.json': JSON.stringify({ general: { defaultApprovalMode: 'turbo' } }) });
  const gemini = result.agents.find(agent => agent.kind === 'gemini');
  assert.equal(level(gemini, 'exec'), 'unknown/auto');
  assert.equal(findingsFor(result, 'AGC-CFG-001').length, 1);
  const plan = scanFiles({ '.gemini/settings.json': JSON.stringify({ general: { defaultApprovalMode: 'plan' } }) });
  assert.equal(findingsFor(plan, 'AGC-CFG-001').length, 0);
});

test('a Bash sandbox is noted as not modelled', () => {
  const result = scanFiles({
    '.claude/settings.json': settings({ allow: ['Bash'] }, { sandbox: { enabled: true } }),
  });
  const [finding] = findingsFor(result, 'AGC-CFG-001');
  assert.match(finding.message, /sandbox\.enabled = "true" is not modelled/);
  const off = scanFiles({ '.claude/settings.json': settings({ allow: ['Bash'] }, { sandbox: { enabled: false } }) });
  assert.equal(findingsFor(off, 'AGC-CFG-001').length, 0);
});

test('a session in dontAsk does not hide what a bypassPermissions or auto subagent can do', () => {
  for (const sub of ['bypassPermissions', 'auto']) {
    const files = mode => ({
      '.claude/settings.json': settings({ defaultMode: mode }),
      '.mcp.json': JSON.stringify({
        mcpServers: { k8s: { command: 'npx', args: ['-y', 'mcp-server-kubernetes@2.0.0'] } },
      }),
      '.claude/agents/worker.md': `---\nname: worker\ndescription: w\npermissionMode: ${sub}\n---\nGo.\n`,
    });
    const worker = result => result.agents.find(agent => agent.kind === 'subagent');
    assert.equal(level(worker(scanFiles(files('dontAsk'))), 'exec'), 'yes/auto', sub);
    assert.equal(level(worker(scanFiles(files('dontAsk'))), 'egress'), 'yes/auto', sub);
    assert.equal(
      worker(scanFiles(files('dontAsk'))).grants.length,
      worker(scanFiles(files('default'))).grants.length,
      `${sub}: the session mode does not change it`,
    );
  }
});

test('disableAllHooks turns every hook off as a runtime check', () => {
  const hooks = { PreToolUse: [{ matcher: '', hooks: [{ type: 'command', command: 'jq -e .tool_input' }] }] };
  const on = scanFiles({ '.claude/settings.json': settings({ allow: ['Bash'] }, { hooks }) });
  const off = scanFiles({
    '.claude/settings.json': settings({ allow: ['Bash'] }, { hooks }),
    '.claude/settings.local.json': settings({}, { disableAllHooks: true }),
  });
  assert.equal(findingsFor(on, 'AGC-COV-001').length, 0);
  assert.equal(findingsFor(off, 'AGC-COV-001').length, 1);
});

test('a sandbox with autoAllowBashIfSandboxed runs Bash without asking, and never lowers egress', () => {
  const sandboxed = scanFiles({ '.claude/settings.json': settings({}, { sandbox: { enabled: true } }) });
  assert.equal(level(main(sandboxed), 'exec'), 'yes/auto');
  assert.equal(level(main(sandboxed), 'egress'), 'yes/ask', 'leaving the sandbox goes through the permission flow');
  // An allowed network command still runs without asking, sandbox or not: the gate must not change.
  const allow = ['mcp__db', 'WebSearch', 'Bash(git push:*)'];
  const mcpFile = JSON.stringify({
    mcpServers: { db: { command: 'npx', args: ['-y', '@modelcontextprotocol/server-postgres@0.6.2'] } },
  });
  const plain = scanFiles({ '.claude/settings.json': settings({ allow }), '.mcp.json': mcpFile });
  const boxed = scanFiles({
    '.claude/settings.json': settings({ allow }, { sandbox: { enabled: true } }),
    '.mcp.json': mcpFile,
  });
  assert.equal(findingsFor(plain, 'AGC-TRI-001').length, 1);
  assert.equal(findingsFor(boxed, 'AGC-TRI-001').length, 1);
  const asking = scanFiles({
    '.claude/settings.json': settings({}, { sandbox: { enabled: true, autoAllowBashIfSandboxed: false } }),
  });
  assert.equal(level(main(asking), 'exec'), 'yes/ask');
});

test('a repository folder named ~ or <managed> is never read as your own or managed settings', () => {
  const risky = {
    '.claude/settings.json': settings({ allow: ['WebFetch', 'mcp__db'] }),
    '.mcp.json': JSON.stringify({
      mcpServers: { db: { command: 'npx', args: ['-y', '@modelcontextprotocol/server-postgres@0.6.2'] } },
    }),
  };
  const before = scanFiles(risky);
  const after = scanFiles({
    ...risky,
    '~/.claude/settings.json': settings({ deny: ['Bash', 'WebSearch', 'WebFetch'] }),
    '<managed>/.claude/settings.json': settings({ defaultMode: 'plan' }),
    '<managed>/managed-settings.json': settings({ deny: ['WebFetch'] }),
  });
  assert.deepEqual(
    after.findings.map(finding => finding.fingerprint).sort(),
    before.findings.map(finding => finding.fingerprint).sort(),
  );
});

test('a settings file padded past 1 MiB fails the gate instead of hiding', () => {
  const result = scanFiles({
    '.claude/settings.json': `${settings({ defaultMode: 'bypassPermissions' })}\n${' '.repeat(1_100_000)}\n`,
  });
  const [finding] = findingsFor(result, 'AGC-CFG-002');
  assert.equal(finding.severity, 'high');
  assert.equal(shouldFail(result.findings, 'high', 'high'), true);
});

test('Codex: a sandbox_mode or approval_policy of the wrong type is reported', () => {
  const result = scanFiles({ '.codex/config.toml': 'sandbox_mode = 3\napproval_policy = true\n' });
  const notes = findingsFor(result, 'AGC-CFG-001').map(finding => finding.message);
  assert.ok(notes.some(text => text.includes('sandbox_mode = "3"')));
  assert.ok(notes.some(text => text.includes('approval_policy = "true"')));
});

test('under a bypassPermissions or auto session, a subagent cannot narrow its own mode', () => {
  for (const session of ['bypassPermissions', 'auto'])
    for (const own of ['dontAsk', 'plan', 'default']) {
      const result = scanFiles({
        '.claude/settings.json': settings({ defaultMode: session }),
        '.claude/agents/w.md': `---\nname: w\ndescription: w\ntools: Bash\npermissionMode: ${own}\n---\nGo.\n`,
      });
      const sub = result.agents.find(agent => agent.kind === 'subagent');
      assert.equal(level(sub, 'exec'), 'yes/auto', `${session} session, ${own} subagent`);
    }
});
