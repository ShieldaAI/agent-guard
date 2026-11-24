# Agent Guard Check plugin: privacy

Last updated: 24 November 2026. Applies to the Agent Guard Check plugin and the
`@shieldaai/agent-guard-check` package it runs.

Shielda receives nothing from this plugin. It has no account, sends no usage data and keeps no
record of what it scanned.

- **What it reads:** agent configuration files in the project you have open (for example
  `.claude/settings.json`, `.mcp.json`, `.codex/config.toml`, workflow files), and git objects
  when it compares your changes with a commit. It reads nothing outside that project.
- **Where results go:** to your agent session on your computer, and nowhere else. The scanner
  writes no files.
- **Network:** to start the scanner, npm downloads the pinned package from the npm registry in
  your npm settings (`registry.npmjs.org` by default). That request is between your computer and
  the registry, under the registry's own privacy terms; it carries what any npm download carries
  (package name and version, your IP address, npm's user agent) and nothing from your project.
  The scanner makes no requests of its own. One case to know: in a partial (blobless) git clone,
  comparing with a commit could make git fetch a missing object from the repository's own remote,
  as any git command there would. The MCP server turns that off; git 2.44 and later honour it,
  and with older git that fetch can still happen.
- **Your agent's model provider:** findings returned to your agent become part of your session,
  which your agent host handles under its own terms, like any other tool output.
- **Personal data and children:** this is a developer tool. It does not set out to process
  personal data; a configuration file it reads may happen to contain some, and that stays on your
  computer. It is not directed at people under 18.

The command-line tool has options that do reach the network (`--live`, `--agent-map-url`,
`--github-repo`). The plugin does not use them.

Questions: [GitHub issues](https://github.com/ShieldaAI/agent-guard/issues) or
support@shielda.ai.
