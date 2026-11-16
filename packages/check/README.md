# @shieldaai/agent-guard-check

Agent permissions now live in files that change in ordinary pull requests: a permission
list, an MCP server, a hook, a CI trigger. One line can turn a harmless agent into one that
reads private data, takes in untrusted text and can send data out. A reviewer sees a JSON
diff, not that consequence.

Agent Guard Check reads those files and shows what each agent in a repository can do. It
flags authority the agent does not need and, on a pull request, reports only what the change
made worse. It reads files only: it never runs repository code, never starts an MCP server
and makes no network calls.

**Status: alpha (0.1.0-alpha.0).** Outside the 1.x compatibility promise. It works without
Agent Guard; reading Agent Guard's own manifests is planned.

```sh
npx @shieldaai/agent-guard-check
```

Node.js 22 or later. One runtime dependency (`yaml`).

## What it shows

```text
agent-guard-check 0.1.0-alpha.0: 1 agent(s), 1 critical, 1 medium

Claude Code (project)  (.claude/settings.json)
  reads private data     yes, no approval    via mcp__postgres
  reads untrusted input  yes, no approval    via WebFetch, WebSearch
  writes                 yes, with approval  via Bash, Edit
  runs code              yes, with approval  via Bash
  sends data out         yes, no approval    via WebFetch, Bash
  runtime check: none

Findings:
  CRITICAL AGC-TRI-001  .claude/settings.json:3
           Claude Code (project) reads private data (mcp__postgres), reads untrusted input (WebFetch) and can send data out without approval (WebFetch).
           Fix: Require approval for "WebFetch", or remove one of the three legs.
  MEDIUM   AGC-COV-001  .claude/settings.json:3
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

## What it reads

| Agent | Files |
| --- | --- |
| Claude Code | `.claude/settings.json`, `.claude/settings.local.json`, `.mcp.json`, `.claude/agents/*.md`, `.claude/commands/*.md`, skills and hook scripts, `CLAUDE.md`, `AGENTS.md` (at any depth, so monorepo packages are separate agents) |
| GitHub workflows | Steps that use `anthropics/claude-code-action`, `openai/codex-action`, or run `claude -p` or `codex exec` |
| VS Code and Cursor | `.vscode/mcp.json`, `.cursor/mcp.json` (comments and trailing commas allowed) |
| Repository | `CODEOWNERS`, root `package.json` (dependencies only), `.agc.yaml` |

`node_modules`, build output and `.git` are skipped. Symbolic links are never followed.
Files over 1 MiB are skipped and counted.

## Pull requests: report only what got worse

```sh
npx @shieldaai/agent-guard-check --base origin/main --format markdown
```

With `--base`, the files at that commit are read with `git show` (nothing is checked out)
and compared with the working tree. The report lists capabilities that grew (from `no` to
`yes`, or from "with approval" to "no approval") and findings that are new. The exit code
depends on new findings only, so existing debt does not block unrelated changes.

A GitHub Actions job:

```yaml
name: Agent config
on: pull_request
permissions:
  contents: read
  security-events: write
jobs:
  check:
    runs-on: ubuntu-latest
    timeout-minutes: 5
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - run: npx -y @shieldaai/agent-guard-check@0.1.0-alpha.0 --base origin/${{ github.base_ref }} --format sarif --output agc.sarif
      - if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: agc.sarif
```

## Options

| Option | Meaning |
| --- | --- |
| `--format text\|json\|sarif\|markdown` | Output format. JSON includes each agent's computed authority. SARIF 2.1.0 works with GitHub code scanning. Markdown is a PR comment. |
| `--output <file>` | Write the report to a file. |
| `--fail-on <severity\|none>` | Exit 1 at or above this severity. Default `high`. |
| `--min-confidence high\|low` | By default, low-confidence findings are reported but never fail the run. |
| `--base <ref>` | Compare with a commit and report only what the change made worse. |
| `--baseline <file>` / `--write-baseline <file>` | Accept current findings once; later runs fail only on new ones. |

Exit codes: `0` nothing at or above `--fail-on`, `1` findings, `2` usage or read error.

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
```

Unknown keys and invalid values are errors, so a typo never silently turns a check off. Every
ignore needs a reason.

In Markdown, YAML and scripts, a comment on the same line or the line above suppresses one
rule: `<!-- agc-ignore AGC-SUP-004: installer pinned by checksum -->`. Settings files are
strict JSON, so use `.agc.yaml` for them. Suppressed findings, with their reasons, are listed
in JSON output.

## Rules

Severity is the default; `.agc.yaml` can change it. Low-confidence rules match text and are
reported without failing the run unless `--min-confidence low` is set.

| ID | Severity | Finding | OWASP |
| --- | --- | --- | --- |
| AGC-PERM-001 | Critical | Agent runs every tool without asking | ASI02, ASI09 |
| AGC-PERM-002 | High | Wildcard tool allow | ASI02 |
| AGC-PERM-003 | High | Allowed command can send data out or run any code | ASI02, ASI05 |
| AGC-PERM-004 | High | Agent can read files outside the project | ASI03 |
| AGC-PERM-005 | Medium | Destructive action allowed without approval | ASI02, ASI09 |
| AGC-TRI-001 | Critical | Lethal trifecta: private data, untrusted input and an unguarded way out | ASI01, ASI02 |
| AGC-TRI-002 | Medium | Lethal trifecta behind one approval, or one leg unknown | ASI01 |
| AGC-SUP-001 | High | MCP server runs an unpinned package | ASI04 |
| AGC-SUP-002 | High | Remote MCP server over plain HTTP | ASI04 |
| AGC-SUP-003 | High | Remote content loaded into the agent at runtime | ASI04, ASI01 |
| AGC-SUP-004 | Critical | Download piped into a shell | ASI04, ASI05 |
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
| AGC-GOV-001 | Low | Agent configuration has no code owner | ASI10 |
| AGC-GOV-002 | Low | Subagent has no stated purpose | ASI10 |
| AGC-COV-001 | Medium | Risky actions with no runtime check | ASI02 |

Some findings change severity with context: AGC-TRG-001 is medium when
`claude-code-action` only answers people with write access, high when anyone can start the
agent, and critical when anyone can start it with broad tools or when a
`pull_request_target` job checks out the pull request's own code.

## How it decides

- **Approval.** Interactive Claude Code asks before shell commands, edits, fetches and MCP
  tool calls unless an allow rule or a permission mode says otherwise. Those paths count as
  "with approval". A headless agent (a workflow step) has nobody to answer a prompt, so only
  its allowed tools count.
- **The trifecta.** Critical when the agent reads private data and untrusted input and can
  send data out without approval. Medium when only the prompt on sending data out stands
  in the way while untrusted input arrives unasked, or when one leg is unknown. When a
  person approves both untrusted input and sending out, it is not reported.
- **Shell commands** are sorted by what they can reach: the project's own test, lint, build
  and install commands; read-only commands; commands that publish to the repository itself
  (`gh pr comment`, `git push`); and commands that can reach any host or run arbitrary code
  (`curl`, `ssh`, `node`, `python`, `npx`). Only the last group is AGC-PERM-003.
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

- It does not detect malicious code inside an MCP server or skill. Content scanners such as
  Cisco MCP Scanner and Snyk Agent Scan cover that.
- It cannot see permissions held outside the repository: a token's real scopes, cloud IAM,
  or user-level settings in `~/.claude`.
- It does not block anything at runtime. Agent Guard does that.
- Text rules are heuristics, labelled low confidence.

## API

```ts
import { scan, diffScans, formatSarif } from '@shieldaai/agent-guard-check';

const head = scan({ root: '/path/to/repo' });
const base = scan({ root: '/path/to/repo', ref: 'origin/main' });
const diff = diffScans(base, head);
console.log(diff.widened.map(change => `${change.agent.name}: ${change.capability}`));
```

`MemorySource` scans files you already hold, without touching the disk.

Apache-2.0.
