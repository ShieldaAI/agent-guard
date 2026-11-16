#!/usr/bin/env node
// Benchmark: `node bench/run.mjs` scores the labeled cases; `--real [--cache dir]` also re-scans
// the pinned public repositories in real-repos.json (needs git and network) and compares the
// critical, high and medium findings with the reviewed results. Prints Markdown.
import { execFileSync } from 'node:child_process';
import { existsSync, mkdirSync, readFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { RULES, scan } from '@shieldaai/agent-guard-check';
import { CASES } from './cases.mjs';
import { scoreCases } from './score.mjs';

const args = process.argv.slice(2);
const pct = value => `${(value * 100).toFixed(1)}%`;
const out = [];
const score = scoreCases(CASES);
out.push('## Labeled cases', '');
out.push(
  `${CASES.length} cases over ${score.rows.length} of ${RULES.length} rules. Precision ${pct(score.precision)}, recall ${pct(score.recall)}.`,
  '',
);
out.push(
  '| Rule | Flagged correctly | Missed | False positives | Correctly quiet |',
  '| --- | --- | --- | --- | --- |',
);
for (const row of score.rows) out.push(`| ${row.rule} | ${row.tp} | ${row.fn} | ${row.fp} | ${row.tn} |`);
if (score.misses.length) out.push('', ...score.misses.map(miss => `- ${miss.kind}: ${miss.id}`));

let failed = score.misses.length > 0;
if (args.includes('--real')) {
  const manifest = JSON.parse(readFileSync(new URL('./real-repos.json', import.meta.url), 'utf8'));
  const cacheIndex = args.indexOf('--cache');
  // A cache under the user's home, not a predictable path in the shared temp folder.
  const cache = cacheIndex >= 0 ? args[cacheIndex + 1] : join(homedir(), '.cache', 'agent-guard-check-bench');
  mkdirSync(cache, { recursive: true, mode: 0o700 });
  let expectedTotal = 0;
  let agents = 0;
  const diffs = [];
  for (const entry of manifest.repos) {
    const dir = join(cache, entry.repo.replace('/', '_'));
    const git = (...rest) => execFileSync('git', ['-C', dir, ...rest], { encoding: 'utf8' }).trim();
    if (!existsSync(dir)) {
      execFileSync('git', ['init', '-q', dir]);
      git('remote', 'add', 'origin', `https://github.com/${entry.repo}`);
    }
    // Check out the pinned commit and scan the working tree, as the CLI does by default.
    let head = '';
    try {
      head = git('rev-parse', 'HEAD');
    } catch {
      head = '';
    }
    if (head !== entry.commit) {
      git('fetch', '-q', '--depth', '1', '--filter=blob:none', 'origin', entry.commit);
      git('checkout', '-q', '--detach', entry.commit);
    }
    const result = scan({ root: dir });
    const got = {};
    for (const finding of result.findings)
      if (['critical', 'high', 'medium'].includes(finding.severity))
        got[`${finding.ruleId}:${finding.severity}`] = (got[`${finding.ruleId}:${finding.severity}`] ?? 0) + 1;
    agents += result.agents.length;
    for (const key of new Set([...Object.keys(got), ...Object.keys(entry.expected)])) {
      expectedTotal += 0;
      if ((got[key] ?? 0) !== (entry.expected[key] ?? 0))
        diffs.push(`- ${entry.repo}: ${key} expected ${entry.expected[key] ?? 0}, got ${got[key] ?? 0}`);
    }
    expectedTotal += Object.values(entry.expected).reduce((a, b) => a + b, 0);
  }
  out.push('', '## Public repositories', '');
  out.push(
    `${manifest.repos.length} repositories at pinned commits, ${agents} agents, ${expectedTotal} reviewed critical/high/medium findings (all true positives when reviewed ${manifest.reviewed}).`,
  );
  out.push(
    diffs.length
      ? ['', 'Differences from the reviewed results:', ...diffs].join('\n')
      : 'Results match the reviewed findings exactly.',
  );
  failed ||= diffs.length > 0;
}
process.stdout.write(`${out.join('\n')}\n`);
process.exitCode = failed ? 1 : 0;
