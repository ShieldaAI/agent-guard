#!/usr/bin/env node
// Benchmark: `node bench/run.mjs` scores the labeled cases; `--real [--cache dir]` also re-scans
// the pinned public repositories in real-repos.json (needs git and network) and compares the
// critical, high and medium findings with the reviewed results. Prints Markdown.
import { execFileSync } from 'node:child_process';
import { existsSync, mkdirSync, readFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { CAPABILITIES, RULES, authority, scan } from '@shieldaai/agent-guard-check';
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
  const falsePositives = manifest.repos.reduce(
    (sum, entry) => sum + Object.values(entry.falsePositives ?? {}).reduce((a, b) => a + b, 0),
    0,
  );
  out.push(
    `${manifest.repos.length} repositories at pinned commits, ${agents} agents, ${expectedTotal} reviewed critical/high/medium findings: ${expectedTotal - falsePositives} true positives, ${falsePositives} false positive(s), precision ${pct((expectedTotal - falsePositives) / expectedTotal)} (reviewed ${manifest.reviewed}).`,
  );
  out.push(
    diffs.length
      ? ['', 'Differences from the reviewed results:', ...diffs].join('\n')
      : 'Results match the reviewed findings exactly.',
  );
  failed ||= diffs.length > 0;

  // Recall against independent labels (recall-labels.json) for 8 of the repositories.
  const labels = JSON.parse(readFileSync(new URL('./recall-labels.json', import.meta.url), 'utf8'));
  const rank = { no: 0, unknown: 1, ask: 2, auto: 3 };
  const levelOf = state => (state.value === 'no' ? 'no' : state.value === 'unknown' ? 'unknown' : state.approval);
  const per = Object.fromEntries(CAPABILITIES.map(c => [c, { yes: 0, detected: 0, level: 0 }]));
  let labelled = 0;
  let found = 0;
  for (const repo of labels.repos) {
    const result = scan({ root: join(cache, repo.repo.replace('/', '_')) });
    for (const item of repo.agents) {
      if (/^\[(extra format|test workflow)\]/.test(item.why ?? '')) continue;
      labelled += 1;
      const file = item.file.replace(/^\.\//, '');
      const matches = result.agents.filter(
        agent =>
          agent.location.file === file ||
          agent.id.includes(file) ||
          (agent.kind === 'plugin' && file.startsWith(agent.id.slice('plugin:'.length).replace(/^\.$/, ''))),
      );
      // A subagent with no tools list or mode of its own is the session again.
      if (!matches.length && item.tool === 'subagent') {
        const dir = file.startsWith('.claude/') ? '.' : file.split('/.claude/')[0];
        const session = result.agents.find(agent => agent.id === `claude-code:${dir}`);
        if (session) matches.push(session);
      }
      if (!matches.length) continue;
      found += 1;
      for (const capability of CAPABILITIES) {
        const want = item.capabilities[capability];
        if (want !== 'ask' && want !== 'auto') continue;
        per[capability].yes += 1;
        const got = matches.map(agent => levelOf(authority(agent)[capability])).sort((a, b) => rank[b] - rank[a])[0];
        if (got !== 'no') per[capability].detected += 1;
        if (got === want || (got === 'auto' && want === 'ask')) per[capability].level += 1;
      }
    }
  }
  const total = Object.values(per).reduce(
    (sum, item) => ({ yes: sum.yes + item.yes, detected: sum.detected + item.detected, level: sum.level + item.level }),
    { yes: 0, detected: 0, level: 0 },
  );
  out.push('', '## Recall against independent labels', '');
  out.push(
    `${labels.repos.length} repositories, ${labelled} labelled agents, ${found} found (${pct(found / labelled)}). Of ${total.yes} capabilities labelled yes: ${pct(total.detected / total.yes)} reported (yes or unknown), ${pct(total.level / total.yes)} at the labelled approval level or wider.`,
    '',
    '| Capability | Labelled yes | Reported | At level |',
    '| --- | --- | --- | --- |',
  );
  for (const [capability, item] of Object.entries(per))
    out.push(
      `| ${capability} | ${item.yes} | ${item.yes ? pct(item.detected / item.yes) : '-'} | ${item.yes ? pct(item.level / item.yes) : '-'} |`,
    );
}
process.stdout.write(`${out.join('\n')}\n`);
process.exitCode = failed ? 1 : 0;
