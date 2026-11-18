---
name: agent-guard-check
description: Check what AI agents in this repository can do before changing their configuration. Use when editing .claude/settings.json, .mcp.json, subagents, Codex or Gemini CLI config, or agent workflows, or when asked whether an agent setup is safe.
---

# Agent Guard Check

`agent-guard-check` reads agent configuration (Claude Code settings, subagents, MCP configs,
Codex and Gemini CLI settings, plugin marketplaces, and GitHub workflows that run agents) and
shows what each agent can do: read private data, take in untrusted input, write, run code, send
data out, spend money, or change its own instructions. It flags authority the agent does not need.
It only reads files. It never runs repository code.

## Before you change agent configuration

1. Note the current state:

   ```sh
   npx --yes @shieldaai/agent-guard-check@1.3.1 . --fail-on none
   ```

2. Make the change.

3. Check what the change made worse, compared with the last commit:

   ```sh
   npx --yes @shieldaai/agent-guard-check@1.3.1 . --base HEAD
   ```

   Exit code 1 means the change added a finding at or above the fail-on severity (high by
   default). Do not hand the change back until you have fixed it or the user has accepted it.

If the `agent-guard-check` MCP server is connected, use its `check_agent_config_change` tool with
`base: "HEAD"` instead of step 3.

## Reading the result

- Each agent is listed with its capabilities: `yes, no approval` is the risky level; `yes, with
  approval` means a person is asked first; `unknown` means the scanner could not tell.
- **AGC-TRI-001** (lethal trifecta) is the most serious: one agent can read private data, read
  untrusted input and send data out, all without approval. Fix it by putting the outbound path
  behind approval (move the rule from `permissions.allow` to `permissions.ask`) or removing one leg.
- Every finding names a file, a line and a fix. `npx --yes @shieldaai/agent-guard-check@1.3.1
  --list-rules` lists all rules.

## Fixing

- `--fix-dry-run` prints safe fixes as a diff; `--fix` applies them. Safe fixes only remove
  authority (bypass modes, unasked risky commands) or add limits (timeouts, turn limits), and each
  is verified by scanning again.
- Never silence a finding without a reason. To accept one, add a comment on the line above it:
  `agc-ignore AGC-XXX-000: <why this is acceptable>`, or an `ignore` entry with a `reason` in
  `.agc.yaml`.

## Do not

- Do not add `bypassPermissions`, `--dangerously-skip-permissions`, `"Bash"` or `"Bash(*)"` to
  allow lists, or `approval_policy = "never"` with full access, to make a task easier.
- Do not paste tokens into `.mcp.json`, settings or workflows. Use environment variables or secrets.
