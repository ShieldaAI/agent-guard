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
agent-guard-check 1.4.0: 1 agent(s), 1 critical, 1 medium
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
           Fix: Add a runtime check that sees these calls: a PreToolUse hook whose matcher names these tools, or route them through Agent Guard or an MCP gateway.
```

That is the whole result for this `.claude/settings.json` and `.mcp.json`:

```json
{ "permissions": { "allow": ["mcp__postgres", "WebFetch"] } }
```

```json
{
  "mcpServers": {
    "postgres": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-postgres@0.6.2", "postgresql://localhost/app"]
    }
  }
}
```

For each agent it works out seven capabilities: reads private data, reads untrusted input,
writes, runs code, sends data out, spends money, changes itself. Each one is `no`,
`unknown`, `yes, with approval` or `yes, no approval`, and names the file and line that
grants it. An unknown capability is never treated as safe.

## Three levels of evidence

| Evidence            | When it runs                                                                                                                                                                      | What it adds                                                                                                                                                                                                                           |
| ------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Repository files    | Always                                                                                                                                                                            | Agents, their capabilities and 36 rules on configuration                                                                                                                                                                               |
| Agent Guard records | When `guard.describe()` output, an executor inventory snapshot or a host manifest is in an `agent-guard*.json` file, named in `agent_guard.files`, or passed with `--agent-guard` | 8 rules (AGC-AGX-*) on the guard itself: tasks exposed to the dangerous three, unapproved or unlabeled tools, wildcard grants, long budgets, unowned agents, access declared outside the guard, MCP servers reachable around the guard |
| Live Agent Map      | Only with `--live` or `--agent-map-url` and a read-only token                                                                                                                     | 4 rules (AGC-DRF-*): activity no declared agent accounts for, unclaimed cloud identities, agents Agent Map flags as exposed in production, stale inventory                                                                             |

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
`agent_map.token_env`, which must end in `AGENT_MAP_TOKEN` (for example `PROD_AGENT_MAP_TOKEN`),
so the repository cannot choose another secret to send. It is never accepted in a file or a
URL. The URL must use `https` (plain `http` only for localhost).

## What it reads

| Agent                    | Files                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| ------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Claude Code              | `.claude/settings.json`, `.claude/settings.local.json`, `.mcp.json`, `.claude/agents/*.md` (including `permissionMode`, `disallowedTools`, inline `mcpServers`, `model`), `.claude/commands/*.md` and skills (including their `allowed-tools`, which run without asking while one is active), hook scripts, `CLAUDE.md`, `AGENTS.md`, up to 32 folders deep, so monorepo packages are separate agents. On macOS and Windows letter case is ignored: a path that is configuration only when case is ignored (`.CLAUDE/settings.json`, a root `claude.md`), and two paths that differ only in case, are reported                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| Claude Code plugins      | `extraKnownMarketplaces` in settings, `.claude-plugin/marketplace.json`; a plugin folder (`.claude-plugin/plugin.json`) is its own agent with its `.mcp.json` servers, `mcpServers` and `hooks` (inline, a file in the plugin, or a list of them) and `hooks/hooks.json`; a file it names that cannot be read counts as unknown reach. A `.mcp.json` there still counts for Claude Code in that folder too                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| Agent Plugins            | `plugin.json` beside `mcp.json` or a `skills/` folder; `SKILL.md` files anywhere under `skills/`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| OpenAI Codex             | `.codex/config.toml`: approval policy, sandbox mode, network access, web search, MCP servers, profiles                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| Gemini CLI               | `.gemini/settings.json` (nested and flat layouts): approval mode, allowed, core and excluded tools, trusted MCP servers, `mcp.allowed`, `GEMINI.md`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| GitHub workflows         | Steps that use `anthropics/claude-code-action` (with its `settings`: inline JSON, a mapping or a file), `openai/codex-action` (with its `sandbox` and `permission-profile`), or run `claude -p` (with `--settings`), `codex exec`, `copilot -p` or `gemini -p`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| GitHub Agentic Workflows | `.github/workflows/*.md` with `on:` in the frontmatter: triggers, `engine` (and its `env`), `tools` (`bash`, `edit`, `web-fetch`, `web-search`, `playwright`, `github` with `read-only` and `github-token`), `safe-outputs` (with `threat-detection` and `jobs`), `permissions`, `env` and `github-token` secrets, `mcp-servers` (including `container`), `network`, and `imports` (front matter, `{{#import}}` and `@include`) from the repository, three levels deep, each relative to the file that names it. The `.lock.yml` it compiles to is judged from this source, except steps that use `claude-code-action`, `codex-action` or `run-gemini-cli`, which gh-aw never generates and which are judged in the lock; a lock with no gh-aw source beside it is read as a workflow and is also unknown reach. With `--base`, a lock that changed while its source did not is reported (AGC-CFG-002, high); without `--base`, a lock edited by hand in other ways is not detected. Frontmatter `jobs`, `steps` and `post-steps` that start an agent are unknown reach (high); `sandbox: { agent: false }` opens the network; a `secrets` mapping is private data |
| VS Code and Cursor       | `.vscode/mcp.json`, `.cursor/mcp.json` (comments and trailing commas allowed), Cursor rules (`.cursor/rules/*.mdc`, `.cursorrules`)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| Cursor CLI               | `.cursor/cli.json`: `Shell`, `Read`, `Write`, `WebFetch` and `Mcp` allow and deny tokens, with the servers in `.cursor/mcp.json`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| OpenCode                 | `opencode.json` or `opencode.jsonc` (also in `.opencode/`): V1 `permission` objects, bash patterns and `<server>_*` keys, V2 `permissions` rules, disabled `tools`, `mcp` servers, `model`; agent overrides in `agent.<name>` and `.opencode/agent/*.md`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| GitHub Copilot           | Custom agents in `.github/agents/*.md` (`tools` with GitHub's and VS Code's tool names, `mcp-servers`, `target`, `model`); `.github/copilot-instructions.md`, `.github/instructions/*.instructions.md` and `.github/prompts/*.prompt.md` for the text rules                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| Kiro                     | `.kiro/settings/mcp.json` (`autoApprove`, `disabled`); `.kiro/steering/*.md` for the text rules                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| Windsurf                 | `.windsurfrules` and `.windsurf/rules/*.md`, for the text rules (its MCP and permission settings live outside the repository)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| Agent Guard              | `agent-guard*.json` records, or files named in `.agc.yaml` or on the command line                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| Repository               | `CODEOWNERS`, `package.json` files (names and dependencies) and package-source files (`.npmrc`, `.yarnrc`, `.yarnrc.yml`, `bunfig.toml`, `uv.toml`, `pip.conf`, `pyproject.toml`) for identification, `.agc.yaml`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| Your own settings        | Only with `--include-user`: `~/.claude/settings.json`, user and local-scope servers in `~/.claude.json`, `~/.codex/config.toml`, `~/.gemini/settings.json` and Claude Code managed settings                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |

`node_modules`, `.git` and virtual environments are skipped. Build output and vendored code
(`dist`, `build`, `out`, `vendor`, `target`, ...) are skipped too, but only outside configuration
folders: a skill called `build` is read. Agent configuration found inside a skipped folder
(`vendor/.claude/settings.json`) is reported as AGC-CFG-002 (high for settings). Links are resolved the way the operating
system resolves them (a `..` after a linked folder included), and followed only when they stay
inside the repository: a linked file is read through its target, and a linked folder is walked
at the link's own path, so `.claude -> tools/agentcfg` is read as `.claude`. In a git tree, a link
whose target passes through another link, or has `..` after a folder name, is not followed. A
link that is not followed is never read. A configuration file the scan could not read is
reported as AGC-CFG-002: one over 1 MiB, a link (to a file or a folder where configuration lives)
that leaves the repository or cannot be resolved, a file that cannot be parsed (invalid JSON,
YAML or TOML, or more YAML aliases than allowed; Claude Code subagents are first read the
lenient way Claude Code reads them), or a walk that stopped (more than 200,000 entries, folders
more than 32 levels deep, or one folder reached through links more than 4 times). Folders and
files where configuration lives are walked first, so filler cannot use up the walk before
`.github` or `.claude`; a walk that stopped is still high. For settings and agent definitions (including subagents, Copilot, OpenCode and gh-aw
agents written in Markdown) it is high and fails the default gate, so padding or linking one
cannot hide what it grants; for instruction files it is medium. An agent whose definition could
not be read, or a file a configuration names (a gh-aw import, a plugin's server or hook file, a
workflow's settings file) that could not be read, counts as unknown reach. A workflow settings
file or a gh-aw import that is not in the repository (or is at a moving ref of another
repository) is reported at high, so moving the risky part out of view fails the gate; a gh-aw
import pinned to a commit of another repository is a note. Folders named `~` or `<managed>` in
the repository are never read.

Amp and Goose keep their permissions outside the repository, so they are not read. Configuration
of agents the scanner does not model (Kiro hooks and agents, Gemini CLI commands, extensions and
`.env`, OpenCode plugins, Roo Code, Continue, Junie, Amazon Q, Crush, Qwen Code, Cursor's
background agent) is reported as AGC-CFG-001: high when it can run code (servers, hooks, plugins),
medium otherwise. Unknown gh-aw front matter keys are reported too (high for ones that run code,
such as `safe-inputs`). Cursor's `hooks.json` is judged like Claude Code's hooks. VS Code's
`chat.tools.autoApprove`, Zed's `always_allow_tool_actions` and Aider's `yes-always` are read as
bypasses (AGC-PERM-001), in `.vscode/settings.json`, `*.code-workspace` and
`.devcontainer/devcontainer.json`; VS Code terminal and URL auto-approve patterns beyond fixed
project commands, Zed context servers and Aider test and lint commands are high. `.env` is never
read, since it holds secrets: Aider settings there are not seen. A setting
the scanner does not model, such as a permission mode or Copilot tool name it does not know, a
gh-aw engine key or tool it does not know, or the domains Claude Code's Bash sandbox allows, is
reported as AGC-CFG-001 with what the scan assumed instead, and the reach it could give is
counted as unknown. An allow rule for a tool the scanner does not know is unknown reach, reported
at medium.

Hooks run without asking, on every matching event, so each one is judged like a command:
hooks in settings, plugin `hooks.json` and skill, command and subagent front matter, and the
commands Claude Code runs on its own (`apiKeyHelper`, `otelHeadersHelper`, `awsAuthRefresh`,
`awsCredentialExport`, `statusLine`, `fileSuggestion`). A hook's command is split into commands
and each is sorted as a Bash rule is (see shell commands below); a script from the repository or
the plugin (`"$CLAUDE_PROJECT_DIR"/.claude/hooks/x.sh`, `python3 scripts/x.py`) is project code,
read for the scripts it runs, unless it pipes a download into a shell. A hook that can reach the
network or run arbitrary code, an HTTP hook, or one that runs a program outside the repository
is AGC-PERM-003. A `PreToolUse` or `PermissionRequest` hook (or a Cursor `beforeShellExecution` /
`beforeMCPExecution` hook) that answers "allow" approves calls instead of a person: the tools it
matches run without asking, it is AGC-PERM-001 (critical), and it is not a runtime check. The
decision is read from the hook's command, the scripts it runs, the files it prints and the local
modules a script imports. A hook may approve (high, and not a runtime check either) when it
builds a decision the scan cannot read (`"permissionDecision": "al" + "low"`, `D=allow`), when
a decision key's value is anything but a literal deny or ask, when its output is decoded or
reversed (base64, `rev`, character codes), or when its text cannot be read (a
script that is missing or outside the repository, an HTTP or prompt hook). Settings `env`
values that run code or change where packages come from are high: shell startup and prefix
variables (`BASH_ENV`, `CLAUDE_CODE_SHELL_PREFIX`, `PATH`), loaders (`LD_PRELOAD`, `NODE_OPTIONS`,
`PYTHONPATH`, `JAVA_TOOL_OPTIONS`, `DOTNET_STARTUP_HOOKS`), git hooks into commands
(`GIT_CONFIG_*`, `GIT_ASKPASS`, `GIT_SSH_COMMAND`), build wrappers (`RUSTC_WRAPPER`, `GOFLAGS`)
and package sources (`npm_config_*`, `PIP_INDEX_URL`, ...).

### Your own settings

What an agent can do on your machine also depends on settings outside the repository. With
`--include-user` the scan merges them in Claude Code's order: managed settings first (their
deny rules always apply, and `disableBypassPermissionsMode` turns bypass off), then the
project's own settings, then yours. Allow and deny rules from every level add up. Servers in
`~/.claude.json` count for every project, and its `projects` entry for this folder for this one
only. Your Codex and Gemini CLI settings are listed as their own agents, `Codex (~)` and
`Gemini CLI (~)`. Findings point at `~/...` paths.

It is for local runs only: in CI these files belong to the runner, so the flag is refused when
`CI` is set. It cannot be combined with `--fix`, which edits repository files only, or with
`--write-baseline`, which would record your own settings as accepted repository findings. A file
it cannot read (over 1 MiB, or not a regular file) is named on stderr. Managed MCP servers
(`managed-mcp.json`) count for every project.

## Pull requests: report only what got worse

```sh
npx @shieldaai/agent-guard-check --base origin/main --format markdown
```

With `--base`, the files at that commit are read with `git` (nothing is checked out) and
compared with the working tree. The report lists capabilities that grew (from `no` to `yes`,
or from "with approval" to "no approval") and findings that are new. A finding whose severity
rose counts as new, and so does a new finding that the same change silences with an inline
`agc-ignore` comment. The exit code depends on new findings only, so existing debt does not
block unrelated changes.

The change under review does not set its own gate: `.agc.yaml`, and a `--baseline` file inside
the repository, are read from the base commit. An edit to either takes effect once it is merged,
and the scanner notes on stderr that the file differs.

### GitHub Action

```yaml
name: Agent config
on: pull_request
permissions:
  contents: read
  pull-requests: write # for comment: true
  security-events: write # for sarif: true
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
comment up to date. It runs an exact package version (input `version`, default `1.4.0`),
from a folder outside the checkout and with the public npm registry, so a `node_modules` or
`.npmrc` committed in the pull request cannot replace the scanner.
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
  allowed_mcp_servers: [github, postgres, mcp/fetch] # catalog ID, package or image (never the config name)
  allowed_mcp_hosts: [mcp.example.com, githubcopilot.com]
  forbid:
    - name: untrusted input with unasked network access
      when: { untrustedInput: auto, egress: auto } # auto: without approval; any: at all
      severity: critical
```

## Review records: an owner and a review date

Agents outlive the people who set them up. `.agc-reviews.yaml` at the repository root gives
each agent the repository ships an owner, the capabilities its last review approved, and a date
by which someone looks again:

```yaml
reviews:
  - agent: .claude/settings.json # agent ID, agent name, or the file that defines it
    owner: '@acme/platform'
    review_by: 2027-05-01 # YYYY-MM-DD, UTC
    capabilities: [write, selfModify] # what it may do without asking; [] for none
  - agent: .github/workflows/triage.yml
    owner: '@acme/support-tools'
    review_by: 2027-02-15
    capabilities: [untrustedInput, write]
```

`agent` matches an agent's ID, its name, or the file that defines it; `--format json` lists
the ID and name of every agent the scan found. `capabilities` lists what the agent may do
without a person approving each use, using the
seven capability names (`privateData`, `untrustedInput`, `write`, `exec`, `egress`, `spend`,
`selfModify`). Something behind a per-call prompt is checked at every call, so it is left out.

A date on its own turns into a snooze button, so the check holds the record to it:

- **The date passing fails the check** (AGC-REV-001, high). No commit makes a date pass, so in
  a pull request the finding counts as new whether or not the base had it. Every change fails
  until the review is done, and a baseline does not silence it. For 14 days before the date it
  is reported as info.
- **A renewal shows what it approves.** With `--base`, a change to a record is listed with the
  date, the owner, the capabilities it approves (and what it approved before) and what the agent
  can do now without asking. The reviewer approves access, not just a later date. A record
  removed by the change is listed too.
- **The record must match the agent.** An agent that can do more without asking than its record
  approves is a finding (AGC-REV-003). So a change that widens access also has to change the
  record, where the reviewer sees it.
- **The date cannot be pushed out of sight.** `review_by` may be at most
  `policy.max_review_days` ahead (default 365; AGC-REV-004).
- **Every agent needs a record**, once `policy.require_reviews: true` is set (AGC-REV-002). A
  record that names no agent (AGC-REV-005), usually left behind by a rename, and one that cannot
  be read (AGC-REV-007) are findings too. A record is never guessed at.
- **The owner should be asked about changes.** When the repository has CODEOWNERS, an owner it
  does not name is reported (AGC-REV-006). That also catches an owner who left and was removed
  from it.

```yaml
# .agc.yaml
policy:
  require_reviews: true
  max_review_days: 180
```

With `--base`, `.agc-reviews.yaml` is read from the change, like agent configuration, so a
renewal is judged on its new date. `.agc.yaml` is read from the base, so a change cannot raise its
own `max_review_days` or turn off `require_reviews`. The scanner cannot tell whether anyone
actually reviewed the agent before moving the date. That decision belongs to the people who
approve the pull request, ideally the owner through CODEOWNERS. What the scanner does is put the
capabilities in front of them.

## Other agents: MCP server and skill

`agent-guard-check-mcp` is a read-only MCP server (stdio) so an agent can check its own
configuration before it changes it. It scans one root fixed at start-up and never leaves it.

```json
{
  "mcpServers": {
    "agent-guard-check": {
      "command": "npx",
      "args": ["-y", "-p", "@shieldaai/agent-guard-check@1.4.0", "agent-guard-check-mcp", "."]
    }
  }
}
```

Tools: `scan_agent_config`, `check_agent_config_change` (compare with a git ref) and
`explain_agent_rule`. A Claude Code skill that tells the agent when to run the check is in
[`skill/agent-guard-check/SKILL.md`](skill/agent-guard-check/SKILL.md).

## Options

| Option                                            | Meaning                                                                                                                                                                                                                              |
| ------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `--format text\|json\|sarif\|markdown\|inventory` | Output format. JSON includes each agent's computed authority. SARIF 2.1.0 works with GitHub code scanning. Markdown is a PR comment. Inventory is an auditor's export: agents, capabilities, tools and counts, without finding text. |
| `--output <file>`                                 | Write the report to a file (owner-only permissions).                                                                                                                                                                                 |
| `--fail-on <severity\|none>`                      | Exit 1 at or above this severity. Default `high`.                                                                                                                                                                                    |
| `--min-confidence high\|low`                      | By default, low-confidence findings are reported but never fail the run.                                                                                                                                                             |
| `--base <ref>`                                    | Compare with a commit and report only what the change made worse.                                                                                                                                                                    |
| `--baseline <file>` / `--write-baseline <file>`   | Accept current findings once; later runs fail only on new ones.                                                                                                                                                                      |
| `--agent-guard <file>`                            | Read an Agent Guard record from anywhere (repeatable).                                                                                                                                                                               |
| `--live`, `--agent-map-url <url>`                 | Add live evidence from Agent Map (read-only).                                                                                                                                                                                        |
| `--import-sarif <file>`                           | Merge another tool's SARIF findings into the report, baseline and gate (repeatable). They keep their own tool name in SARIF output.                                                                                                  |
| `--fix`, `--fix-dry-run`                          | Apply or print verified safe fixes.                                                                                                                                                                                                  |
| `--include-user`                                  | Also read your own settings outside the repository (local runs only). See [Your own settings](#your-own-settings).                                                                                                                   |
| `--list-rules`                                    | Print every rule.                                                                                                                                                                                                                    |

Exit codes: `0` nothing at or above `--fail-on`, `1` findings, `2` usage, read or live-evidence error.

## Configuration and suppressions

`.agc.yaml` at the repository root:

```yaml
fail_on: high # critical, high, medium, low, info or none
min_confidence: high # high or low
severity:
  AGC-LIM-002: info
ignore:
  - rule: AGC-SUP-001
    path: tools/ # optional: a file or folder
    reason: Served from our internal registry mirror, pinned there.
agent_guard:
  files: [build/agent-guard-description.json]
  max_deadline_hours: 24 # AGC-AGX-007 ceilings
  max_calls: 1000
  max_cost: 500
agent_map:
  url: https://agent-map.internal.example
  token_env: AGENT_MAP_TOKEN
policy: {} # see Policy as code and Review records
mcp_servers: # what servers the catalog does not know can do
  mcp.docs.example.com: # a package, image, remote host or catalog ID
    capabilities: [untrustedInput]
  '@acme/crm-mcp':
    capabilities: [privateData, write]
    unknown: [egress]
```

Unknown keys and invalid values are errors, so a typo never silently turns a check off. Every
ignore needs a reason.

`mcp_servers` declares what an MCP server can do: the capabilities it has, and the ones it may
have (`unknown`). Anything not listed is `no`, and `[]` means it can do none of the seven. A
declaration is keyed by what runs: the package (`npx`, `uvx` and similar), the container image,
the remote host, or a catalog ID, and it replaces the built-in catalog entry. It never matches a
server's name in the config, because a change chooses names: a server called `docs` that runs
another package is not the declared one. With `--base`, declarations are read from the base
commit like the rest of `.agc.yaml`.

A package or image is identified, for the catalog and for declarations, only when the command
has exactly the expected shape: a runner (`npx`, `uvx`, `bunx`, `pipx run`, `pnpm dlx`,
`yarn dlx`, `npm exec`) with only harmless flags (`-y`, `--quiet`, `--offline` and similar), then
the package and its own arguments; or `docker run` / `podman run` with known flags, then the
image. `-p`/`--package`/`--from`, `--call`, a registry or any other runner flag, a shell line
with a second command (`sh -c "npx pkg; curl ..."`), `--entrypoint`, `--env-file`, an unknown
docker flag, an environment variable that changes what is loaded (`NODE_OPTIONS`,
`npm_config_*`, `PYTHONPATH`, `LD_PRELOAD`, ...) or an `envFile`, a docker mount or working folder
(`-v`, `--mount`, `-w`, which can replace the image's code), or a server with both a command and a
URL all leave it unidentified, so its reach stays unknown. So do a package spec that fetches from
somewhere other than the registry (`name@npm:other`, `name@github:...`, `name@file:...`, a URL,
`name @ git+https://...`), a package the repository's own `package.json` depends on (a runner
resolves that from the dependency spec; so is any package named or depended on by a
`package.json` anywhere in the repository), a runner or `docker` that is a file in the repository
(`./bin/npx`) rather than a system command, a server with a `cwd`, a docker environment
variable that changes the daemon (`DOCKER_HOST`, ...), and a package from a registry the
repository redirects: an npm-family runner below a `.npmrc`, `.yarnrc(.yml)` or `bunfig.toml`
that sets a registry, or `uvx`/`pipx` below a `uv.toml`, `pip.conf` or `pyproject.toml` that sets
an index. Settings that do not redirect (`engine-strict`, hoisting) change nothing, and a
redirect applies only to its own folder and below; one that is too large or a link out of the
repository is assumed to redirect. The policy rule (AGC-POL-001) matches servers the same way,
also by remote host, and AGC-SUP-001 checks every package a command fetches, reporting a shell
line it cannot read. A server that is not identified may read private data, take in untrusted
input, send data out, write and run code: all unknown.

In Markdown, YAML and scripts, a comment on the same line or the line above suppresses one
rule: `<!-- agc-ignore AGC-SUP-004: installer pinned by checksum -->`. Settings files are
strict JSON, so use `.agc.yaml` for them. Suppressed findings, with their reasons, are listed
in JSON output.

## Rules

Severity is the default; `.agc.yaml` can change it. The [rule catalog](docs/rules.md) shows,
for every rule, a configuration it flags and a look-alike it does not.

| ID           | Severity                | Finding                                                                 | OWASP        |
| ------------ | ----------------------- | ----------------------------------------------------------------------- | ------------ |
| AGC-PERM-001 | Critical                | Agent runs every tool without asking                                    | ASI02, ASI09 |
| AGC-PERM-002 | High                    | Wildcard tool allow                                                     | ASI02        |
| AGC-PERM-003 | High                    | Allowed command can send data out or run any code                       | ASI02, ASI05 |
| AGC-PERM-004 | High                    | Agent can read files outside the project                                | ASI03        |
| AGC-PERM-005 | Medium                  | Destructive action allowed without approval                             | ASI02, ASI09 |
| AGC-PERM-006 | High                    | Subagent runs with broader permissions than its parent                  | ASI02, ASI09 |
| AGC-TRI-001  | Critical                | Lethal trifecta: private data, untrusted input and an unguarded way out | ASI01, ASI02 |
| AGC-TRI-002  | Medium                  | Lethal trifecta behind one approval, or one leg unknown                 | ASI01        |
| AGC-SUP-001  | High                    | MCP server runs an unpinned package                                     | ASI04        |
| AGC-SUP-002  | High                    | Remote MCP server over plain HTTP                                       | ASI04        |
| AGC-SUP-003  | High                    | Remote content loaded into the agent at runtime                         | ASI04, ASI01 |
| AGC-SUP-004  | Critical                | Download piped into a shell                                             | ASI04, ASI05 |
| AGC-SUP-005  | Medium                  | Plugin or marketplace not pinned                                        | ASI04        |
| AGC-PER-001  | High                    | Agent can rewrite its own instructions                                  | ASI06, ASI10 |
| AGC-PER-002  | High                    | Agent can change its own permissions or hooks                           | ASI10        |
| AGC-SEC-001  | Critical                | Hardcoded credential                                                    | ASI03        |
| AGC-SEC-002  | Medium                  | Secret passed on a command line                                         | ASI03        |
| AGC-TXT-001  | Medium (low confidence) | Hidden characters in agent instructions                                 | ASI01, ASI06 |
| AGC-TXT-002  | Medium (low confidence) | Instruction-override phrasing in shipped prompts                        | ASI01        |
| AGC-TXT-003  | Low (low confidence)    | Long encoded blob in agent instructions                                 | ASI01        |
| AGC-TXT-004  | Medium (low confidence) | Instructions to act without asking                                      | ASI02, ASI09 |
| AGC-TRG-001  | High                    | Agent triggered by outsiders with write access                          | ASI01, ASI03 |
| AGC-LIM-001  | Low                     | No turn limit on an automated agent                                     | ASI08        |
| AGC-LIM-002  | Low                     | No timeout on an automated agent                                        | ASI08        |
| AGC-IDN-001  | High                    | Agent runs on a personal access token                                   | ASI03        |
| AGC-TRG-002  | Medium                  | Unattended agent changes the repository with no reviewer                | ASI09, ASI08 |
| AGC-IDN-002  | Medium                  | Agent gets long-lived cloud keys                                        | ASI03        |
| AGC-GOV-001  | Low                     | Agent configuration has no code owner                                   | ASI10        |
| AGC-GOV-002  | Low                     | Subagent has no stated purpose                                          | ASI10        |
| AGC-COV-001  | Medium                  | Risky actions with no runtime check                                     | ASI02        |
| AGC-GOV-003  | Info                    | Agent model is a moving alias                                           | ASI04        |
| AGC-CFG-001  | Info (low confidence)   | Agent setting the scanner does not model                                | ASI02        |
| AGC-CFG-002  | High                    | Agent configuration file too large to read                              | ASI02, ASI04 |
| AGC-REV-001  | High                    | Agent review date has passed                                            | ASI10        |
| AGC-REV-002  | High                    | Agent has no review record                                              | ASI10        |
| AGC-REV-003  | High                    | Agent can do more than its review approved                              | ASI02, ASI10 |
| AGC-REV-004  | High                    | Agent review date is too far away                                       | ASI10        |
| AGC-REV-005  | Medium                  | Review record matches no agent                                          | ASI10        |
| AGC-REV-006  | Low                     | Review owner is not a code owner                                        | ASI10        |
| AGC-REV-007  | High                    | Review record could not be read                                         | ASI10        |
| AGC-POL-001  | High                    | MCP server not on the approved list                                     | ASI04        |
| AGC-POL-002  | High                    | Remote MCP server on a host not on the approved list                    | ASI04, ASI02 |
| AGC-POL-003  | High                    | Agent holds a forbidden capability combination                          | ASI02, ASI01 |
| AGC-AGX-001  | High                    | Agent reaches a guarded MCP server directly                             | ASI02        |
| AGC-AGX-002  | High                    | Declared access outside the guard                                       | ASI02, ASI03 |
| AGC-AGX-003  | Critical                | Agent Guard task exposed to the dangerous three                         | ASI01, ASI02 |
| AGC-AGX-004  | Medium                  | Agent without an owner, or retired with live work                       | ASI10        |
| AGC-AGX-005  | Medium                  | Guarded tool registered but not approved                                | ASI04        |
| AGC-AGX-006  | Medium                  | Task grant broader than its tool warrants                               | ASI02, ASI03 |
| AGC-AGX-007  | Medium                  | Task budget above the team ceiling                                      | ASI08        |
| AGC-AGX-008  | Medium                  | Outbound tool labels leave a gap                                        | ASI02        |
| AGC-DRF-001  | High                    | Guarded activity no declared agent accounts for                         | ASI10, ASI03 |
| AGC-DRF-002  | Medium                  | Cloud identities no agent claims                                        | ASI03        |
| AGC-DRF-003  | High                    | Live agent exposed to the dangerous three                               | ASI01, ASI02 |
| AGC-DRF-004  | Low                     | Live inventory is stale                                                 | ASI10        |

Some findings change severity with context: AGC-TRG-001 is medium when
`claude-code-action` only answers people with write access, high when anyone can start the
agent, and critical when anyone can start it with broad tools or when a
`pull_request_target` job checks out the pull request's own code.

## Accuracy

Three measurements, all reproducible with `npm run bench:check` (and `--real` for the last two):

- **Labeled cases.** 129 configurations, at least one that each of the 48 rules must flag and
  one look-alike it must not (`bench/cases.mjs`). Precision 100%, recall 100%. The test suite
  fails if a rule loses its cases or any case changes outcome.
- **Public repositories.** 32 repositories at pinned commits (Anthropic, OpenAI, Google,
  Microsoft, Sentry, PostHog, Supabase, Vercel and others; `bench/real-repos.json`), 191 agents.
  Every critical, high and medium finding, 178 in all, was reviewed by hand: 177 true positives
  and 1 false positive (a low-confidence text rule), precision 99.4%. "True" follows the
  fail-closed reading above: `Bash(git *)` or `Bash(rg:*)` is reported because an option can run
  any program, and a local MCP server the scanner cannot identify is reported when its tools run
  without asking.
- **Recall against independent labels.** For 8 of those repositories, a reviewer who saw neither
  the scanner's output nor its source labelled every agent and its seven capabilities from the
  configuration files (`bench/recall-labels.json`). The scanner finds 68 of the 70 agents
  (97%). Of the 300 capabilities labelled yes it reports 84% (as yes or unknown), and 67% at the
  labelled approval level or wider:

  | Capability     | Labelled yes | Reported | At level |
  | -------------- | ------------ | -------- | -------- |
  | untrustedInput | 64           | 92%      | 81%      |
  | write          | 58           | 93%      | 71%      |
  | egress         | 56           | 96%      | 73%      |
  | exec           | 48           | 98%      | 79%      |
  | privateData    | 29           | 55%      | 21%      |
  | selfModify     | 23           | 96%      | 96%      |
  | spend          | 22           | 0%       | 0%       |

  Most of the gap is a difference in definitions, not a missed setting. The labels count money
  spent by any command that runs unsandboxed and data read outside the project after a prompt;
  the scanner counts spending only through a tool known to spend, and private data only where
  the agent reaches it without a person approving that read (otherwise every agent that can
  fetch a web page would be a lethal trifecta). It also does not see what a prompt tells the
  agent to fetch, or what a later job does with the agent's output. The two agents it misses
  are an OpenCode CLI started from a workflow script and an empty desktop plugin.

## How it decides

- **Approval.** Interactive Claude Code asks before shell commands, edits, fetches and MCP
  tool calls unless an allow rule or a permission mode says otherwise. Those paths count as
  "with approval". A headless agent (a workflow step) has nobody to answer a prompt, so only
  its allowed tools count. A subagent's `permissionMode` replaces the session's for its calls.
- **Permission modes.** `bypassPermissions` runs every tool without asking. `auto` lets a
  classifier, not a person, approve most calls, so they count as "no approval"; that safety
  review checks the calls the mode lets through, so it counts as a runtime check for them
  (AGC-COV-001), in sessions and in workflows (`--permission-mode auto`) alike. Calls an allow
  rule already permits do not reach it. Project settings with `defaultMode: auto` are reported
  as AGC-PERM-001 (medium). `dontAsk`
  denies whatever would prompt, so only allowed tools remain. `acceptEdits` also runs `mkdir`,
  `touch`, `mv` and `cp` without asking. `plan` and `manual` read like `default`. Newer Claude
  Code ignores `auto` and `bypassPermissions` in project settings; the scan still reports them,
  because older versions apply them.
- **The trifecta.** Critical when the agent reads private data and untrusted input and can
  send data out without approval. Medium when only the prompt on sending data out stands
  in the way while untrusted input arrives unasked, or when one leg is unknown. When a
  person approves both untrusted input and sending out, it is not reported.
- **Shell commands** are sorted by what they can reach: the project's own test, lint, build
  and install commands and package scripts (`npm test`, `pnpm lint`, `./scripts/check.sh`);
  read-only commands; commands that bring in remote text (`git clone`, `git pull`); commands that
  change files (`cp`, `mv`, `tee`, `git reset`); commands that publish to the repository itself
  (`gh pr comment`, `git push`); and everything else, counted as commands that can reach any host
  or run arbitrary code (AGC-PERM-003). The sort fails closed: a rule is narrower only when
  every command in it matches a known command shape. An exact rule is split the way a shell
  would (`ls && curl … | sh` is as wide as `curl` and `sh`), a redirect writes a file, and options
  that run a program are read (`awk 'BEGIN{system(…)}'`, `sed e`, `find -exec`, `git -c`,
  `rg --pre`, `sort --compress-program`, `tar --to-command`). Prefix rules for `git fetch`,
  `pull`, `clone` and `remote` reach the network (`--upload-pack` runs a program), and ones for
  `git diff`, `log` and `show` write files (`--output`). A star with no space before it
  (`git diff*`, `ls*`) matches other programs and subcommands (`git difftool`, `lsof`), so it
  counts as running code; a path glob (`tests/*`) and a package-script prefix (`pnpm test*`) do
  not. Harmless exact commands are not reported: version and help checks (`node --version`),
  listings (`docker ps`, `pip list`, `kubectl get`) and workspace scripts (`pnpm --filter web
test`, `yarn workspace web test`, `turbo run test`, `bundle exec rspec`). An unknown program, an absolute path to one, a wrapper that runs
  another command (`sudo`, `timeout`, `xargs`, `env`, `eval`), a wildcard inside the command
  (`c*`, `*url`) and a prefix rule for a command whose options run programs (`git:*`, `find:*`,
  `rg:*`, `sort:*`, `sed:*`, `awk:*`, `git rebase:*`, `git grep:*`) all count as running code;
  so do prefix rules that choose what to install or run (`npm install:*`, `npm exec:*`,
  `uv run:*`, `bun run:*`, `mvn:*`, `tox:*`, `nx:*`, `yarn plugin:*`, `pnpm up:*`), and prefix rules for build tools whose options run any program (`make:*`,
  `go test:*`, `cargo:*`, `just:*`). A rule for a repository script is read: a script that runs
  its arguments as a command (`exec "$@"`, `eval "$*"`, `sys.argv` handed to a process) allows
  any command. Variable assignments before a command are dropped unless they load code
  (`BASH_ENV`, `PATH`, `GIT_SSH_COMMAND`, ...). `PowerShell` and `Monitor` rules are judged as Bash
  rules are; `WebFetch(domain:*)` sends data out.
- **Codex** runs commands inside its sandbox without asking unless `approval_policy` is
  `untrusted`; `workspace-write` has no network unless `network_access = true`; leaving the
  sandbox needs approval unless the policy is `never`. `never` with `danger-full-access` is
  AGC-PERM-001. **Gemini CLI** asks before built-in tools unless they are in `tools.allowed`
  or the approval mode is `yolo`; a trusted MCP server skips confirmation for all its tools.
- **MCP servers.** A catalog of 44 well-known servers (GitHub, Slack, Postgres, Fetch,
  Playwright, Exa, Zapier, Kubernetes and others) records what each can do, by package, image
  or remote host. Any other server is unknown until `mcp_servers` in `.agc.yaml` declares it.
- **Sandbox.** With Claude Code's `sandbox.enabled`, sandboxed Bash runs and writes without
  asking unless `autoAllowBashIfSandboxed` is false. The sandbox never lowers network reach: a
  command can leave it (`allowUnsandboxedCommands`, `excludedCommands`) through the normal
  permission flow, where an allowed command still runs without asking, and the sandbox's allowed
  domains are not modelled.
- **Actions.** Agent actions are matched by name in any letter case, with any sub-path
  (`anthropics/claude-code-action/base-action`) and under any owner, so a fork counts. A local
  composite action (`uses: ./` or `uses: ./path`) is read step by step, through the local actions
  it uses, three levels deep; one that starts an agent is an agent of unknown reach, reported at
  high. Every `--mcp-config` file and `mcp_config` given as a path is read, relative to the
  step's `working-directory` for a CLI; one that cannot be read makes the step unknown reach.
- **Scripts.** A `run:` script is split into commands the way a shell would: quotes removed,
  shell keywords (`if`, `then`, `do`, `!`), variable assignments, `env`, `time`, `sudo`,
  `timeout`, `xargs`, `npx` and other wrappers skipped, and `bash -c "..."`, `eval "..."`,
  `$(...)` and back quotes read as commands of their own. The scan follows repository scripts the
  step runs (`./ci/agent.sh`, `bash x.sh`, `source x.sh`), files run by an interpreter
  (`python3 ci/x.py`, `node x.js`, `ruby x.rb`, `uv run python x.py`: a process call there that
  starts an agent CLI, such as `subprocess.run(["claude", "-p", ...])`, is an agent of unknown
  reach, and so are local modules they import), `npm run` / `pnpm` scripts from `package.json`
  (with their `pre` and `post` scripts, `npm test` / `start` and install lifecycle scripts),
  `make`, `just` and Taskfile targets, Dockerfile `RUN` lines for `docker build`, `find -exec`,
  aliases and symlinks to an agent CLI, a custom `shell:`, the agent CLI inside `docker run`,
  and Claude Code started as `node .../cli.js` or by path (`"$(which claude)"`). Shell variables
  set in the script or in `env` are expanded; an unquoted variable the scan cannot resolve
  (`$FLAGS`, `"$@"`, `"${ARGS[@]}"`), a quoted one not named for a prompt (`"$MODE"`), or a GitHub expression
  where a flag could be (`claude_args: ${{ inputs.args }}`, any argument holding text an outsider
  chose, such as `--model ${{ github.event.comment.body }}`) makes the step unknown reach. An
  agent named in text the scan cannot follow (piped into a shell, `python -c` code that starts a
  process, a command taken from the job's matrix, a non-shell `shell:`, a `github-script` that
  starts a process, decoded text piped into a shell such as `base64 -d | bash`, a step in a job
  container named for an agent) is an agent of unknown reach. So is a remote action or reusable
  workflow handed agent flags or a model key. Flags of the Claude Code and Codex CLIs the scan
  does not know (`--plugin-dir`, `--chrome`, `--add-dir` outside the checkout, Codex
  `-c mcp_servers.…`) make the step unknown reach; Codex's attached `-sdanger-full-access` is read,
  and a `CODEX_HOME` in the repository is read (elsewhere, unknown). A step that writes agent
  settings or adds servers before the agent runs (`> ~/.claude/settings.json`,
  `claude mcp add`) makes the agent unknown reach, and so do gh-aw front matter steps that do.
  `claude-code-base-action` does not check who starts it. OpenCode, Cursor's CLI, Aider, Amp, Goose, Qwen
  Code and Crush, and actions that run them, are agents of unknown reach too. `claude --version`,
  `npm i -g @anthropic-ai/claude-code`, `claude mcp add`, `command -v claude` or an `echo` that
  mentions an agent are not agents. Claude Code's list flags are variadic
  (`--allowedTools Read Bash`). Action inputs are matched in any letter case, as GitHub matches
  them. `path_to_claude_code_executable`, `plugins`, `plugin_marketplaces`,
  `--permission-prompt-tool` and inline `--agents` that set a permission mode make the step
  unknown reach; `allowed_bots: "*"` lets any bot start it. `CLAUDE_CONFIG_DIR` or `HOME` set
  for a Claude step moves its settings: the file it points to in the repository is read, and one
  outside the repository makes the step unknown reach.
- **Workflow agents.** A Codex step runs commands without asking, inside its sandbox:
  `read-only` writes nothing, `workspace-write` writes the checkout, and the network is unknown
  unless the sandbox is `danger-full-access`; a permission profile, defined in Codex's own config,
  leaves writes unknown. A workflow agent with a GitHub token and a shell can read issue and
  pull-request text whatever started it, so that input is unknown. When flags and inputs set
  different Codex sandboxes (`--sandbox read-only --full-auto`), the wider one is judged.
  `claude-code-action`'s `settings` (inline JSON with comments, a mapping or a file in the
  repository), `--settings`, and `claude -p --permission-mode` are read; settings that cannot be
  read make the step unknown reach. Copilot CLI steps (`copilot -p`) and Gemini CLI steps
  (`gemini`, `gemini-cli` or `npx @google/gemini-cli` in command position, with `-p`, a positional
  prompt or stdin, or the `google-github-actions/run-gemini-cli` action) are unknown reach, or run
  every tool without asking with `--allow-all-tools` / `--yolo`. A GitHub
  Agentic Workflow is unattended; its `safe-outputs` are posted by a separate job that checks
  them, which counts as a runtime check for them unless `threat-detection` is off. Imported tool
  lists are joined. An engine gh-aw does not build in, an import that cannot be read (from
  another repository, missing, too large or nested too deep), a tool the scanner does not model,
  or custom safe-output `jobs` are unknown reach, as are engine settings it does not model
  (`args`, `command`, ...) and container MCP servers with an entrypoint, mounts or arguments.
  Secrets in the agent's `env`, its MCP servers, its tools and its engine's environment (which its
  shell inherits) are private data, except the model credentials the harness itself reads (see
  workflow triggers below). Imported `jobs` and `steps` that start an agent, and engine `command`,
  `steps` or `args` that lift the agent's limits, are unknown reach, reported at high. With
  `network: { allowed: ["*"] }` the firewall is open, so outbound reach is yes. The repository a
  workflow runs in is not counted as private data.
- **gh-aw lock files.** The `.lock.yml` that runs is checked against its source's front matter
  (and the front matter it imports; prose explains nothing). Untrusted triggers the source does
  not have (after gh-aw's own expansion of `slash_command` and `label_command`), agent flags it
  does not ask for in `engine.args` or `engine.permission-mode` (`--dangerously-skip-permissions`,
  `--permission-mode bypassPermissions` in either form, `--allow-all-tools` without
  `bash: "*"`), Claude allowed tools its tools do not give (every Bash command, web fetches,
  edits; the list read the way Claude Code reads it), an agent CLI other than the source's
  engine, or an agent gh-aw does not compile mean the lock was edited by hand: it is unknown
  reach, reported at high. A `frontmatter_hash` that differs from the
  source's (gh-aw's own algorithm, recomputed) means the lock is out of date or edited: medium.
  Other hand edits to compiled steps are not detected; recompiling in CI (`gh aw compile` and a
  diff) is the complete check.
- **Model endpoints.** `ANTHROPIC_BASE_URL` and similar variables send model traffic, with
  everything the agent reads, to another endpoint. That is reported (AGC-CFG-001) but not counted
  as sending data out, since it is the model's own channel. In the repository's settings, a
  workflow or a gh-aw engine it is high, except for a model provider's own host
  (`https://api.z.ai/...`) or a value set outside the repository (`${{ vars.X }}`), which are
  medium; proxies and CA bundles are medium.
- **IDE agents.** The VS Code and Cursor agents behind `.vscode/mcp.json` and `.cursor/mcp.json`
  ask before terminal commands and fetches, apply edits without asking, and ask before MCP tools.
- **Changing itself.** An agent that can edit any file, or run any shell command, can rewrite its
  own settings and instructions, with the same approval.
- **Workflow triggers.** `issues`, `issue_comment`, `pull_request_target`, discussions and
  `workflow_run` carry text anyone can write and run with the repository's secrets.
  `pull_request` from forks gets no secrets and a read-only token, so it is not treated as
  outsider input. Commands that post to the repository count only when the job's token can
  write. A reusable workflow (`workflow_call`) takes the triggers of its callers in the
  repository; with no caller here, anyone's event may start it (unknown). Secrets are found in
  every expression form (`secrets.X`, `secrets['X']`, `toJSON(secrets)` for all of them), in every
  input but the harness's own credentials (the prompt included), in the script of a CLI step, and
  through `$GITHUB_ENV` from an earlier step. The harness's own credentials are not counted as
  data given to the agent: a variable it reads (`ANTHROPIC_API_KEY`, `OPENAI_API_KEY`,
  `GEMINI_API_KEY`, `OTEL_EXPORTER_OTLP_HEADERS`, ...), matched by exact name, whose value is a
  secret named for a model provider (`ZAI_API_KEY`) or, for telemetry headers, a telemetry
  service. The same variable carrying another secret (`ANTHROPIC_API_KEY:
${{ secrets.PROD_DB_API_KEY }}`) is counted.
- **The gate and computed reach.** An agent that can both run code and send data out without
  approval, with no runtime check that sees those calls, is AGC-COV-001 at high, whichever
  setting gave it that reach (a Codex `danger-full-access` sandbox, a Bash rule, a mode). An
  agent that can edit any file and run a project command without asking can rewrite that
  command's code, so its network reach is counted as unknown.
- **What the scan does not see.** It reads files; it does not run anything, so a determined
  author can still hide reach from it. Known gaps:
  - code that builds an agent's name at run time (`os.system("cla" + "ude …")` without agent
    flags on that line);
  - a container image's own entry point, a program installed outside the repository, and a
    remote action or reusable workflow that gets neither agent flags nor a model key;
  - settings an earlier step writes somewhere other than the agent's settings files or
    `$GITHUB_ENV` / `$GITHUB_PATH`;
  - Codex permission profiles, Gemini policy files, Copilot and Windsurf hook files, and the
    auth headers of a remote MCP server;
  - `Bash(tee:*)`, `Bash(yq:*)` and similar prefix rules count as writes, not as reaching the
    agent's own settings;
  - `.env` is never read, since it holds secrets.

  In a full scan an inline `agc-ignore` comment can silence a finding in the same change; only
  `--base` judges a change against the base commit's suppressions. Recompiling gh-aw workflows in
  CI is the complete check for lock files.

- **Runtime checks.** A runtime check counts only for the calls it sees. A hook matcher is a
  regular expression from the repository, so the scanner never runs it: it reads the matcher's
  `|` alternatives, and credits only exact tool names (`Bash`), name prefixes (`Web.*`,
  `mcp__db__.*`) and every tool (`""`, `*`, `.*`). For an MCP server an alternative must be a
  prefix of all its tools (`mcp__.*`, `mcp__<server>__.*`): naming one tool does not cover the
  server. Any other shape, a matcher that is not a valid regular expression on its own, or one
  longer than 512 characters is not credited, nor is a hook that can approve calls or whose
  decisions cannot be read (see hooks above), and no hook counts when `disableAllHooks` is set
  (or only managed hooks, under managed `allowManagedHooksOnly`). Agent
  Guard or an MCP gateway reached as an MCP server sees only the calls made through that server,
  not Bash and not servers configured beside it.
- **Other agents.** Codex runs commands inside its sandbox without asking unless
  `approval_policy` is `untrusted`, and an unknown `sandbox_mode` is judged as no sandbox.
  OpenCode V1 allows tools its `permission` object leaves out, V2 asks for calls no rule
  matches, and a file with neither is reported as unknown. Every OpenCode agent override is
  judged (V1 and V2 files, `permission` and `tools`), and the OpenCode agent can do what any of
  its agents can. A Copilot custom agent on the cloud
  agent runs without anyone approving it; its network is behind the Copilot firewall, so
  outbound reach is unknown, and it has the read-only GitHub MCP server unless `tools` leaves it
  out. With `target: vscode` it runs in VS Code, which asks before terminal commands, fetches
  and MCP tools. Tool-set names (`execute/runInTerminal`) count as their set. A tool name the
  scanner does not know, or a `tools` value that is not a list, counts as unknown reach. Kiro's
  `autoApprove` runs the listed tools without a prompt. A plugin's servers ask before their
  tools run, as Claude Code does by default.

## What it does not do

- It does not detect malicious code inside an MCP server, plugin or skill. Content scanners
  such as Cisco MCP Scanner and Snyk Agent Scan cover that; `--import-sarif` merges their
  findings into one report.
- Without Agent Guard records or live evidence it cannot see permissions held outside the
  repository: a token's real scopes or cloud IAM. User-level settings in `~/.claude`,
  `~/.codex` and `~/.gemini` are read only with `--include-user`.
- It does not block anything at runtime. Agent Guard does that.
- Text rules are heuristics, labelled low confidence.

## Inventory format

`--format inventory` writes every agent, its seven capabilities with how each is reached and
the settings behind it, its tools, runtime checks and finding counts, without finding text.
The format is published as a JSON Schema,
[`agent-guard-check-inventory-v1.schema.json`](../../schemas/agent-guard-check-inventory-v1.schema.json),
so other tools can read it or write it. A capability that is not listed is `no`; `unknown` is
never a promise of `no`. New agent kinds may be added in a minor release, so readers should
accept kinds they do not know.

## Security

The scanner treats every file as hostile input. It never executes repository content or runs a
regular expression taken from it, follows a symbolic link only when the operating system
resolves it to a place inside the repository (and reads named files only through paths with no
link in them), caps file sizes and counts, validates git refs before passing them to
`git`, writes reports and baselines with owner-only permissions, masks secrets in messages,
escapes untrusted text in Markdown (including line breaks, mentions and links) and keeps it on
one line in text output, so a name in a repository file cannot start a GitHub workflow command. Network access happens only for live evidence you ask for,
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
