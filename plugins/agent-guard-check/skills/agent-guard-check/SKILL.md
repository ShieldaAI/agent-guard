---
name: agent-guard-check
description: Shows what each AI agent configured in a repository can do and flags authority it does not need. Use before and after changing agent configuration (Claude Code settings and subagents, .mcp.json, Codex or Gemini settings, Copilot custom agents, plugin marketplaces, workflows that run agents), when reviewing a pull request that touches it, or when asked whether an agent setup is safe.
license: Apache-2.0
---

# Agent Guard Check

Agent Guard Check reads agent configuration and lists what each agent is allowed to do (reach
private data or untrusted input, write, run code, send data out, spend, change itself) and whether
a person approves it first. It flags authority the agent does not need, with a file, a line and a
fix for each finding. It only reads files and never runs repository code.

## Use the MCP tools if you have them

If the read-only `agent-guard-check` MCP tools are available in this session (the plugin adds
them where the host can run a local server), prefer them over the command line:

| Task | Tool |
| --- | --- |
| See every agent's authority and all findings | `scan_agent_config` (optional `path` inside the project, `minSeverity`) |
| Check a change before you hand it back | `check_agent_config_change` with `base: "HEAD"` (or the branch the change merges into, such as `origin/main`) |
| Explain a rule ID from a finding | `explain_agent_rule` with `id`, such as `AGC-TRI-001` |

## When you change agent configuration

1. Before editing, run `scan_agent_config` and note what the agents can do now.
2. Make the change.
3. Run `check_agent_config_change` with `base: "HEAD"`. It reports only what the change made
   worse: authority that grew and new findings.
4. If it reports a finding at high or critical severity, fix it or ask the user to accept it
   before you hand the change back. Say which finding it is and why it matters.

If `check_agent_config_change` says git failed (a folder that is not a git repository, or one
with no commits yet), use `scan_agent_config` before and after instead and compare the two.

## Without the MCP tools

Run the scanner with npx (Node.js 22 or newer). Start it from a folder outside the repository and
pass the repository's path, so the repository's own `.npmrc` or `node_modules` cannot change which
scanner runs. The parentheses keep your shell in the repository afterwards:

```sh
repo="$(git rev-parse --show-toplevel)"
(cd "$(mktemp -d)" && npx --yes @shieldaai/agent-guard-check@1.6.2 "$repo" --base HEAD)
```

Leave out `--base HEAD` to list every finding instead of only what the change added. Exit code 1
means a finding at or above the fail-on severity (high by default); 2 is a usage or read error.
The first run downloads the package from npm; if your sandbox blocks network access, ask the user
to allow this command or to run it themselves.

## Reading the result

- Each agent is listed with its capabilities. `yes, no approval` is the risky level; `yes, with
  approval` means a person is asked first; `unknown` means the scanner could not tell, and is
  treated as a risk.
- AGC-TRI-001 (lethal trifecta) is the most serious finding: one agent can read private data, read
  untrusted input and send data out, all without approval. Fix it by putting the outbound path
  behind approval (move the rule from `permissions.allow` to `permissions.ask`) or by removing one
  of the three.
- Every finding names a file, a line and a fix. `explain_agent_rule` (or `--list-rules` on the
  command line) gives the reasoning.

## Fixing

- Prefer removing authority over adding exceptions: narrow an allow rule, move it to ask, pin an
  MCP server to an exact version, drop a bypass mode.
- On the command line, `--fix-dry-run` prints the safe fixes as a diff without changing anything.
  Apply the ones you agree with using your normal edit tools, so the user sees and approves each
  change, then check again.
- Never silence a finding to finish a task. If the user accepts one, record why: a comment
  `agc-ignore AGC-XXX-000: <reason>` on the line above it, or an `ignore` entry with a `reason` in
  `.agc.yaml`.

## Do not

- Do not add `bypassPermissions`, `--dangerously-skip-permissions`, `"Bash"` or `"Bash(*)"` to
  allow lists, or `approval_policy = "never"` with full access, to make a task easier.
- Do not paste tokens into `.mcp.json`, settings or workflows. Use environment variables or
  secrets.
- Do not treat a clean scan as proof that an agent is safe: the scanner judges configuration, not
  what a server or tool does at run time.
