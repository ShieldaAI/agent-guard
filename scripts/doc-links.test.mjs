import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';

const root = resolve(new URL('..', import.meta.url).pathname);

/** Every relative Markdown link in a tracked .md file resolves to an existing path. */
export function brokenLinks() {
  const files = execFileSync('git', ['ls-files', '*.md'], { cwd: root, encoding: 'utf8' }).split('\n').filter(Boolean);
  const broken = [];
  for (const file of files) {
    const text = readFileSync(join(root, file), 'utf8')
      .replace(/```[\s\S]*?```/g, '')
      .replace(/`[^`\n]*`/g, '');
    for (const match of text.matchAll(/\]\(([^)\s]+)(?:\s+"[^"]*")?\)/g)) {
      const target = match[1];
      if (/^(?:[a-z][a-z0-9+.-]*:|#|<)/i.test(target)) continue;
      const path = decodeURIComponent(target.split('#')[0]);
      if (!path) continue;
      if (!existsSync(resolve(join(root, dirname(file)), path))) broken.push(`${file} -> ${target}`);
    }
  }
  return broken;
}

test('relative Markdown links resolve', () => {
  assert.deepEqual(brokenLinks(), []);
});
