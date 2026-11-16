import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { TOOL_VERSION } from '@shieldaai/agent-guard-check';

const read = path => readFileSync(new URL(path, import.meta.url), 'utf8');
const version = JSON.parse(read('../package.json')).version;

// Every place that pins the package version must move with it on a release.
test('version references match package.json', () => {
  assert.equal(TOOL_VERSION, version);
  const places = {
    'action/action.yml': read('../action/action.yml'),
    'skill/agent-guard-check/SKILL.md': read('../skill/agent-guard-check/SKILL.md'),
    'README.md': read('../README.md'),
    '.pre-commit-hooks.yaml': read('../../../.pre-commit-hooks.yaml'),
  };
  for (const [path, text] of Object.entries(places)) {
    const pinned = [
      ...text.matchAll(
        /agent-guard-check@(\d+\.\d+\.\d+[\w.-]*)|default: (\d+\.\d+\.\d+)|agent-guard-check (\d+\.\d+\.\d+)/g,
      ),
    ].map(match => match[1] ?? match[2] ?? match[3]);
    assert.ok(pinned.length > 0, `${path} pins no version`);
    for (const value of pinned) assert.equal(value, version, `${path} pins ${value}`);
  }
});

test('the action pins third-party actions by commit', () => {
  const action = read('../action/action.yml');
  for (const match of action.matchAll(/uses:\s*([^\s#]+)/g)) assert.match(match[1], /@[0-9a-f]{40}$/, match[1]);
});
