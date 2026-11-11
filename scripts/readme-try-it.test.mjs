import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';

const root = new URL('..', import.meta.url);

test('the README five-minute example runs and prints what the README promises', () => {
  const readme = readFileSync(new URL('README.md', root), 'utf8');
  const section = readme.slice(readme.indexOf('## Try it in five minutes'));
  const code = /```js\n([\s\S]*?)```/.exec(section)[1];
  const output = execFileSync(process.execPath, ['--input-type=module', '-e', code], { cwd: root, encoding: 'utf8' });
  assert.equal(output, 'denied: GRANT_DENIED\ndeleted 42\n');
  assert.match(section, /It prints `denied: GRANT_DENIED`, then `deleted 42`\./);
});
