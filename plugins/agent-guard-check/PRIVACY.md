# Agent Guard Check plugin: privacy

Last updated: 24 November 2026. Applies to the Agent Guard Check plugin and the
`@shieldaai/agent-guard-check` package it runs.

**The plugin collects no data.** Shielda receives nothing from it: no telemetry, no analytics, no
crash reports, no account and no identifiers.

- **What it reads:** agent configuration files in the project you have open (for example
  `.claude/settings.json`, `.mcp.json`, `.codex/config.toml`, workflow files), and git history when
  you ask it to compare with a commit. It reads nothing outside that project.
- **Where results go:** only to your agent session on your computer. The scanner keeps no copy and
  writes no files.
- **Network:** the scanner itself makes no network calls. To start it, npm downloads the pinned
  package from the npm registry in your npm settings (`registry.npmjs.org` by default). That
  request is between your computer and the registry, under the registry's own privacy terms; it
  carries what any npm download carries (package name and version, your IP address, npm's user
  agent) and nothing from your project.
- **Your agent's model provider:** findings returned to your agent become part of your session,
  which your agent host handles under its own terms, like any other tool output.
- **Personal data and children:** the plugin is a developer tool. It does not process personal
  data on purpose; a file it reads may happen to contain some, and that stays on your computer.
  It is not directed at people under 18.

Optional features of the command-line tool that do reach the network (`--live`,
`--agent-map-url`, `--github-repo`) are not used by the plugin.

Questions: [GitHub issues](https://github.com/ShieldaAI/agent-guard/issues) or
support@shielda.ai.
