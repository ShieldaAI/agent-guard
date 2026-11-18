// Variants from the ninth review round. Synthetic configs only.
import test from 'node:test';
import assert from 'node:assert/strict';
import { scanFiles } from './helpers.mjs';
import { bashScope } from '../dist/claude.js';

const wf = run =>
  `on: issue_comment\npermissions:\n  contents: write\n  issues: write\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - run: |\n${run
    .split('\n')
    .map(line => `          ${line}`)
    .join('\n')}\n        env:\n          BODY: \${{ github.event.comment.body }}\n`;
const fails = result => result.findings.some(item => item.severity === 'high' || item.severity === 'critical');
const py =
  'import os, subprocess\nsubprocess.run(["claude", "-p", os.environ["BODY"], "--dangerously-skip-permissions"])\n';

for (const [name, files] of Object.entries({
  python: { '.github/workflows/a.yml': wf('python3 ci/triage.py'), 'ci/triage.py': py },
  'uv run python': { '.github/workflows/a.yml': wf('uv run python ci/triage.py'), 'ci/triage.py': py },
  node: {
    '.github/workflows/a.yml': wf('node ci/t.js'),
    'ci/t.js': 'require("child_process").execSync("claude -p hi --dangerously-skip-permissions")\n',
  },
  ruby: {
    '.github/workflows/a.yml': wf('ruby ci/t.rb'),
    'ci/t.rb': 'system("claude -p hi --dangerously-skip-permissions")\n',
  },
  'quoted array': { '.github/workflows/a.yml': wf('ARGS=(-p hi --dangerously-skip-permissions)\nclaude "${ARGS[@]}"') },
  'shell function': { '.github/workflows/a.yml': wf('ai(){ claude -p hi --dangerously-skip-permissions; }\nai') },
  'find -exec': {
    '.github/workflows/a.yml': wf('find . -name x -exec claude -p hi --dangerously-skip-permissions \;'),
  },
}))
  test(`an agent started from ${name} is found`, () => assert.ok(fails(scanFiles(files)), name));

test('a script that only mentions an agent is not one', () => {
  const result = scanFiles({
    '.github/workflows/a.yml': wf('python3 ci/report.py'),
    'ci/report.py': 'import subprocess\nsubprocess.run(["git", "log"])\nprint("claude")\n',
  });
  assert.equal(result.agents.filter(agent => agent.kind === 'workflow').length, 0);
});

test('a ./ path that climbs out of the project is not a project script', () => {
  assert.equal(bashScope('./../../../../usr/bin/curl:*'), 'network');
  assert.equal(bashScope('./../../bin/sh:*'), 'network');
  assert.equal(bashScope('./scripts/ok.sh:*'), 'project');
});
