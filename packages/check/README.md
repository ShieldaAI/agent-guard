# @shieldaai/agent-guard-check

Agent permissions now live in files that change in ordinary pull requests: a permission
list, an MCP server, a hook, a CI trigger, a plugin marketplace. One line can turn a harmless
agent into one that reads private data, takes in untrusted text and can send data out. A
reviewer sees a JSON diff, not that consequence.

Agent Guard Check reads those files and shows what each agent in a repository can do. It
flags authority the agent does not need and, on a pull request, reports only what the change
made worse. By default it reads files only: it never runs repository code, never starts an MCP
server and makes no network calls.

It works on its own. With [Agent Guard](../../README.md) it also reads the guard's own records
(tool labels, live task grants, host manifests), and with a running Agent Map it compares the
repository with what is deployed.

```sh
npx @shieldaai/agent-guard-check
```

Node.js 22 or later. Two runtime dependencies (`yaml`, `smol-toml`), both pinned.

## What it shows

```text
agent-guard-check 1.2.0: 1 agent(s), 1 critical, 1 medium
Evidence: repository files

Claude Code (project)  (.claude/settings.json)
  reads private data     yes, no approval    via mcp__postgres
  reads untrusted input  yes, no approval    via WebFetch, WebSearch
  writes                 yes, with approval  via Bash, Edit
  runs code              yes, with approval  via Bash
  sends data out         yes, no approval    via WebFetch, Bash
  runtime check: none

Findings:
  CRITICAL AGC-TRI-001  .claude/settings.json:1
           Claude Code (project) reads private data (mcp__postgres), reads untrusted input (WebFetch) and can send data out without approval (WebFetch).
           Fix: Require approval for "WebFetch", or remove one of the three legs.
  MEDIUM   AGC-COV-001  .claude/settings.json:1
           Claude Code (project) can send data out without approval (WebFetch), and nothing checks those calls at runtime.
           Fix: Add a runtime check: Agent Guard, a PreToolUse hook, or an MCP gateway.
```

That is the whole result for this `.claude/settings.json` and `.mcp.json`:

```json
{ "permissions": { "allow": ["mcp__postgres", "WebFetch"] } }
```

```json
{ "mcpServers": { "postgres": { "command": "npx", "args": ["-y", "@modelcontextprotocol/server-postgres@0.6.2", "postgresql://localhost/app"] } } }
```

For each agent it works out seven capabilities: reads private data, reads untrusted input,
writes, runs code, sends data out, spends money, changes itself. Each one is `no`,
`unknown`, `yes, with approval` or `yes, no approval`, and names the file and line that
grants it. An unknown capability is never treated as safe.

## Three levels of evidence

| Evidence | When it runs | What it adds |
| --- | --- | --- |
| Repository files | Always | Agents, their capabilities and 34 rules on configuration |
| Agent Guard records | When `guard.describe()` output, an executor inventory snapshot or a host manifest is in an `agent-guard*.json` file, named in `agent_guard.files`, or passed with `--agent-guard` | 8 rules (AGC-AGX-*) on the guard itself: tasks exposed to the dangerous three, unapproved or unlabeled tools, wildcard grants, long budgets, unowned agents, access declared outside the guard, MCP servers reachable around the guard |
| Live Agent Map | Only with `--live` or `--agent-map-url` and a read-only token | 4 rules (AGC-DRF-*): activity no declared agent accounts for, unclaimed cloud identities, agents Agent Map flags as exposed in production, stale inventory |

Files named `agent-guard*.json` are read automatically, and what each one is (describe() output,
inventory snapshot or manifest) is recognised from its content. Name any other path in
`agent_guard.files`, or pass `--agent-guard`. Write a description at build time:

```ts
import { writeFileSync } from 'node:fs';
writeFileSync('agent-guard-description.json', JSON.stringify(guard.describe(), null, 2));
```

The dangerous-three verdicts follow Agent Map's own rules, so the scanner and the map agree:
private data from a sensitive task or a confidential or restricted binding, outside content
from an untrusted task or a tool that reads untrusted content, and a sender that declares
`sendsExternal: true` and stays on `untrustedContext: 'allow'`. The core refuses external
sends from sensitive tasks and tasks without recipients, and so does the scanner.

Live evidence is three read-only queries (`get_inventory_health`, `list_unclaimed_identities`,
`list_agents`). The token comes from `AGENT_MAP_TOKEN`, or the variable named in
`agent_map.token_env`; it is never accepted in a file or a URL. The URL must use `https`
(plain `http` only for localhost).

## What it reads

| Agent | Files |
| --- | --- |
| Claude Code | `.claude/settings.json`, `.claude/settings.local.json`, `.mcp.json`, `.claude/agents/*.md` (including `permissionMode`, `disallowedTools`, inline `mcpServers`, `model`), `.claude/commands/*.md`, skills and hook scripts, `CLAUDE.md`, `AGENTS.md`, at any depth, so monorepo packages are separate agents |
| Claude Code plugins | `extraKnownMarketplaces` in settings, `.claude-plugin/marketplace.json` |
| OpenAI Codex | `.codex/config.toml`: approval policy, sandbox mode, network access, web search, MCP servers, profiles |
| Gemini CLI | `.gemini/settings.json` (nested and flat layouts): approval mode, allowed, core and excluded tools, trusted MCP servers, `mcp.allowed`, `GEMINI.md` |
| GitHub workflows | Steps that use `anthropics/claude-code-action`, `openai/codex-action`, or run `claude -p` or `codex exec` |
| VS Code and Cursor | `.vscode/mcp.json`, `.cursor/mcp.json` (comments and trailing commas allowed) |
| Agent Guard | `agent-guard*.json` records, or files named in `.agc.yaml` or on the command line |
| Repository | `CODEOWNERS`, root `package.json` (dependencies only), `.agc.yaml` |

`node_modules`, build output and `.git` are skipped. Symbolic links are never followed.
Files over 1 MiB are skipped and counted.

## Pull requests: report only what got worse

```sh
npx @shieldaai/agent-guard-check --base origin/main --format markdown
```

With `--base`, the files at that commit are read with `git` (nothing is checked out) and
compared with the working tree. The report lists capabilities that grew (from `no` to `yes`,
or from "with approval" to "no approval") and findings that are new. The exit code depends on
new findings only, so existing debt does not block unrelated changes.

### GitHub Action

```yaml
name: Agent config
on: pull_request
permissions:
  contents: read
  pull-requests: write     # for comment: true
  security-events: write   # for sarif: true
jobs:
  check:
    runs-on: ubuntu-latest
    timeout-minutes: 5
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
      - uses: ShieldaAI/agent-guard/packages/check/action@<commit>
        with:
          comment: true
          sarif: true
```

On pull requests the action compares with the base commit by itself, writes the Markdown
report to the job summary, optionally uploads SARIF to code scanning and keeps one pull-request
comment up to date. It runs an exact package version (input `version`, default `1.2.0`).
Inputs: `path`, `fail-on`, `base`, `baseline`, `agent-guard-files`, `sarif`, `comment`,
`version`.

### pre-commit

```yaml
repos:
  - repo: https://github.com/ShieldaAI/agent-guard
    rev: <release tag or commit>
    hooks:
      - id: agent-guard-check
```

The hook runs with `--base HEAD` when agent configuration is staged.

### Container

```sh
docker build -f packages/check/Dockerfile -t agent-guard-check .
docker run --rm --network none -v "$PWD:/repo:ro" agent-guard-check
```

The image runs as an unprivileged user and needs no network.

## Fixing

```sh
npx @shieldaai/agent-guard-check --fix-dry-run   # print the fixes as a diff
npx @shieldaai/agent-guard-check --fix           # apply them, then report what is left
```

Fixes only remove authority or add limits: they set `defaultMode` back to `default`, move
risky allow rules (network commands, interpreters, self-edits, destructive commands, the
outbound leg of a trifecta) to `ask`, drop bypass flags from workflow steps, and add
`timeout-minutes` and `--max-turns` to agent steps. Each edit is kept only if scanning again
shows its finding gone and nothing as severe added. JSON files with comments and YAML block
scalars are left for a person.

## Policy as code

A `policy` section in `.agc.yaml` encodes a team's own decisions, so reviews do not
re-derive them for each change:

```yaml
policy:
  allowed_mcp_servers: [github, postgres, mcp/fetch]   # config name, catalog ID, package or image
  allowed_mcp_hosts: [mcp.example.com, githubcopilot.com]
  forbid:
    - name: untrusted input with unasked network access
      when: { untrustedInput: auto, egress: auto }      # auto: without approval; any: at all
      severity: critical
```

## Other agents: MCP server and skill

`agent-guard-check-mcp` is a read-only MCP server (stdio) so an agent can check its own
configuration before it changes it. It scans one root fixed at start-up and never leaves it.

```json
{ "mcpServers": { "agent-guard-check": { "command": "npx", "args": ["-y", "-p", "@shieldaai/agent-guard-check@1.2.0", "agent-guard-check-mcp", "."] } } }
```

Tools: `scan_agent_config`, `check_agent_config_change` (compare with a git ref) and
`explain_agent_rule`. A Claude Code skill that tells the agent when to run the check is in
[`skill/agent-guard-check/SKILL.md`](skill/agent-guard-check/SKILL.md).

## Options

| Option | Meaning |
| --- | --- |
| `--format text\|json\|sarif\|markdown\|inventory` | Output format. JSON includes each agent's computed authority. SARIF 2.1.0 works with GitHub code scanning. Markdown is a PR comment. Inventory is an auditor's export: agents, capabilities, tools and counts, without finding text. |
| `--output <file>` | Write the report to a file (owner-only permissions). |
| `--fail-on <severity\|none>` | Exit 1 at or above this severity. Default `high`. |
| `--min-confidence high\|low` | By default, low-confidence findings are reported but never fail the run. |
| `--base <ref>` | Compare with a commit and report only what the change made worse. |
| `--baseline <file>` / `--write-baseline <file>` | Accept current findings once; later runs fail only on new ones. |
| `--agent-guard <file>` | Read an Agent Guard record from anywhere (repeatable). |
| `--live`, `--agent-map-url <url>` | Add live evidence from Agent Map (read-only). |
| `--import-sarif <file>` | Merge another tool's SARIF findings into the report, baseline and gate (repeatable). They keep their own tool name in SARIF output. |
| `--fix`, `--fix-dry-run` | Apply or print verified safe fixes. |
| `--list-rules` | Print every rule. |

Exit codes: `0` nothing at or above `--fail-on`, `1` findings, `2` usage, read or live-evidence error.

## Configuration and suppressions

`.agc.yaml` at the repository root:

```yaml
fail_on: high          # critical, high, medium, low, info or none
min_confidence: high   # high or low
severity:
  AGC-LIM-002: info
ignore:
  - rule: AGC-SUP-001
    path: tools/          # optional: a file or folder
    reason: Served from our internal registry mirror, pinned there.
agent_guard:
  files: [build/agent-guard-description.json]
  max_deadline_hours: 24  # AGC-AGX-007 ceilings
  max_calls: 1000
  max_cost: 500
agent_map:
  url: https://agent-map.internal.example
  token_env: AGENT_MAP_TOKEN
policy: {}                # see Policy as code
```

Unknown keys and invalid values are errors, so a typo never silently turns a check off. Every
ignore needs a reason.

In Markdown, YAML and scripts, a comment on the same line or the line above suppresses one
rule: `<!-- agc-ignore AGC-SUP-004: installer pinned by checksum -->`. Settings files are
strict JSON, so use `.agc.yaml` for them. Suppressed findings, with their reasons, are listed
in JSON output.

## Rules

Severity is the default; `.agc.yaml` can change it. The [rule catalog](docs/rules.md) shows,
for every rule, a configuration it flags and a look-alike it does not.

| ID | Severity | Finding | OWASP |
| --- | --- | --- | --- |
| AGC-PERM-001 | Critical | Agent runs every tool without asking | ASI02, ASI09 |
| AGC-PERM-002 | High | Wildcard tool allow | ASI02 |
| AGC-PERM-003 | High | Allowed command can send data out or run any code | ASI02, ASI05 |
| AGC-PERM-004 | High | Agent can read files outside the project | ASI03 |
| AGC-PERM-005 | Medium | Destructive action allowed without approval | ASI02, ASI09 |
| AGC-PERM-006 | High | Subagent runs with broader permissions than its parent | ASI02, ASI09 |
| AGC-TRI-001 | Critical | Lethal trifecta: private data, untrusted input and an unguarded way out | ASI01, ASI02 |
| AGC-TRI-002 | Medium | Lethal trifecta behind one approval, or one leg unknown | ASI01 |
| AGC-SUP-001 | High | MCP server runs an unpinned package | ASI04 |
| AGC-SUP-002 | High | Remote MCP server over plain HTTP | ASI04 |
| AGC-SUP-003 | High | Remote content loaded into the agent at runtime | ASI04, ASI01 |
| AGC-SUP-004 | Critical | Download piped into a shell | ASI04, ASI05 |
| AGC-SUP-005 | Medium | Plugin or marketplace not pinned | ASI04 |
| AGC-PER-001 | High | Agent can rewrite its own instructions | ASI06, ASI10 |
| AGC-PER-002 | High | Agent can change its own permissions or hooks | ASI10 |
| AGC-SEC-001 | Critical | Hardcoded credential | ASI03 |
| AGC-SEC-002 | Medium | Secret passed on a command line | ASI03 |
| AGC-TXT-001 | Medium (low confidence) | Hidden characters in agent instructions | ASI01, ASI06 |
| AGC-TXT-002 | Medium (low confidence) | Instruction-override phrasing in shipped prompts | ASI01 |
| AGC-TXT-003 | Low (low confidence) | Long encoded blob in agent instructions | ASI01 |
| AGC-TXT-004 | Medium (low confidence) | Instructions to act without asking | ASI02, ASI09 |
| AGC-TRG-001 | High | Agent triggered by outsiders with write access | ASI01, ASI03 |
| AGC-LIM-001 | Low | No turn limit on an automated agent | ASI08 |
| AGC-LIM-002 | Low | No timeout on an automated agent | ASI08 |
| AGC-IDN-001 | High | Agent runs on a personal access token | ASI03 |
| AGC-TRG-002 | Medium | Unattended agent changes the repository with no reviewer | ASI09, ASI08 |
| AGC-IDN-002 | Medium | Agent gets long-lived cloud keys | ASI03 |
| AGC-GOV-001 | Low | Agent configuration has no code owner | ASI10 |
| AGC-GOV-002 | Low | Subagent has no stated purpose | ASI10 |
| AGC-COV-001 | Medium | Risky actions with no runtime check | ASI02 |
| AGC-GOV-003 | Info | Agent model is a moving alias | ASI04 |
| AGC-POL-001 | High | MCP server not on the approved list | ASI04 |
| AGC-POL-002 | High | Remote MCP server on a host not on the approved list | ASI04, ASI02 |
| AGC-POL-003 | High | Agent holds a forbidden capability combination | ASI02, ASI01 |
| AGC-AGX-001 | High | Agent reaches a guarded MCP server directly | ASI02 |
| AGC-AGX-002 | High | Declared access outside the guard | ASI02, ASI03 |
| AGC-AGX-003 | Critical | Agent Guard task exposed to the dangerous three | ASI01, ASI02 |
| AGC-AGX-004 | Medium | Agent without an owner, or retired with live work | ASI10 |
| AGC-AGX-005 | Medium | Guarded tool registered but not approved | ASI04 |
| AGC-AGX-006 | Medium | Task grant broader than its tool warrants | ASI02, ASI03 |
| AGC-AGX-007 | Medium | Task budget above the team ceiling | ASI08 |
| AGC-AGX-008 | Medium | Outbound tool labels leave a gap | ASI02 |
| AGC-DRF-001 | High | Guarded activity no declared agent accounts for | ASI10, ASI03 |
| AGC-DRF-002 | Medium | Cloud identities no agent claims | ASI03 |
| AGC-DRF-003 | High | Live agent exposed to the dangerous three | ASI01, ASI02 |
| AGC-DRF-004 | Low | Live inventory is stale | ASI10 |

Some findings change severity with context: AGC-TRG-001 is medium when
`claude-code-action` only answers people with write access, high when anyone can start the
agent, and critical when anyone can start it with broad tools or when a
`pull_request_target` job checks out the pull request's own code.

## Accuracy

Two measurements, both reproducible with `npm run bench:check` (and `--real` for the second):

- **Labeled cases.** 112 configurations, at least one that each of the 46 rules must flag and
  one look-alike it must not (`bench/cases.mjs`). Precision 100%, recall 100%. The test suite
  fails if a rule loses its cases or any case changes outcome.
- **Public repositories.** 32 repositories at pinned commits (Anthropic, OpenAI, Google,
  Microsoft, Sentry, PostHog, Supabase, Vercel and others; `bench/real-repos.json`), 74 agents.
  Every critical, high and medium finding, 27 in all, was reviewed by hand: all true positives.
  Recall on real repositories is not measured, because no ground truth exists for them.

## How it decides

- **Approval.** Interactive Claude Code asks before shell commands, edits, fetches and MCP
  tool calls unless an allow rule or a permission mode says otherwise. Those paths count as
  "with approval". A headless agent (a workflow step) has nobody to answer a prompt, so only
  its allowed tools count. A subagent's `permissionMode` replaces the session's for its calls.
- **The trifecta.** Critical when the agent reads private data and untrusted input and can
  send data out without approval. Medium when only the prompt on sending data out stands
  in the way while untrusted input arrives unasked, or when one leg is unknown. When a
  person approves both untrusted input and sending out, it is not reported.
- **Shell commands** are sorted by what they can reach: the project's own test, lint, build
  and install commands; read-only commands; commands that publish to the repository itself
  (`gh pr comment`, `git push`); and commands that can reach any host or run arbitrary code
  (`curl`, `ssh`, `node`, `python`, `npx`). Only the last group is AGC-PERM-003.
- **Codex** runs commands inside its sandbox without asking unless `approval_policy` is
  `untrusted`; `workspace-write` has no network unless `network_access = true`; leaving the
  sandbox needs approval unless the policy is `never`. `never` with `danger-full-access` is
  AGC-PERM-001. **Gemini CLI** asks before built-in tools unless they are in `tools.allowed`
  or the approval mode is `yolo`; a trusted MCP server skips confirmation for all its tools.
- **MCP servers.** A short catalog of well-known servers (GitHub, Slack, Postgres, Fetch,
  Playwright and others) records what each can do. Any other server is unknown.
- **Workflow triggers.** `issues`, `issue_comment`, `pull_request_target`, discussions and
  `workflow_run` carry text anyone can write and run with the repository's secrets.
  `pull_request` from forks gets no secrets and a read-only token, so it is not treated as
  outsider input. Commands that post to the repository count only when the job's token can
  write. Secrets in environment variables the harness itself reads (`OTEL_*`,
  `ANTHROPIC_*`, `CLAUDE_CODE_*`) are not counted as data given to the agent.
- **Runtime checks.** AGC-COV-001 credits Agent Guard, any `PreToolUse` hook and MCP
  gateways equally.

## What it does not do

- It does not detect malicious code inside an MCP server, plugin or skill. Content scanners
  such as Cisco MCP Scanner and Snyk Agent Scan cover that; `--import-sarif` merges their
  findings into one report.
- Without Agent Guard records or live evidence it cannot see permissions held outside the
  repository: a token's real scopes, cloud IAM, or user-level settings in `~/.claude`,
  `~/.codex` and `~/.gemini`.
- It does not block anything at runtime. Agent Guard does that.
- Text rules are heuristics, labelled low confidence.

## Security

The scanner treats every file as hostile input. It never executes repository content, never
follows symbolic links, caps file sizes and counts, validates git refs before passing them to
`git`, writes reports and baselines with owner-only permissions, masks secrets in messages and
escapes untrusted text in Markdown. Network access happens only for live evidence you ask for,
with redirects refused and responses capped at 8 MiB. Report problems as described in
[SECURITY.md](../../SECURITY.md).

## API

```ts
import { scan, diffScans, fetchLiveEvidence, formatSarif } from '@shieldaai/agent-guard-check';

const head = scan({ root: '/path/to/repo' });
const base = scan({ root: '/path/to/repo', ref: 'origin/main' });
const diff = diffScans(base, head);
console.log(diff.widened.map(change => `${change.agent.name}: ${change.capability}`));

// With live evidence (read-only token):
const live = await fetchLiveEvidence({ url: 'https://agent-map.example', token: process.env.AGENT_MAP_TOKEN! });
const result = scan({ root: '/path/to/repo', live });
```

`MemorySource` scans files you already hold, without touching the disk. `planFixes`,
`importSarif`, `formatInventory` and the rule list (`RULES`) are exported too.

Apache-2.0.
