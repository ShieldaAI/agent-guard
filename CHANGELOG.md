# Changelog

## Unreleased

### Agent Guard Check

- Feature: review records. `.agc-reviews.yaml` gives each agent an owner, the capabilities its
  last review approved it to do without asking, and a `review_by` date. Seven rules hold the
  record to it. AGC-REV-001 (high) fires once the date passes. A passing date is not a change,
  so in a pull request it counts as new whether or not the base had it, and a baseline does not
  silence it. It is info for the 14 days before the date. AGC-REV-002 requires a record for every
  shipped agent (with `policy.require_reviews`). AGC-REV-003 flags an agent that can do more
  without asking than its record approves. AGC-REV-004 caps how far ahead the date may be
  (`policy.max_review_days`, default 365). AGC-REV-005 (high) flags a record that matches no
  agent, so moving an agent cannot carry new access past its record, AGC-REV-006 an owner
  CODEOWNERS does not name, and AGC-REV-007 a record that cannot be read. An inline `agc-ignore`
  comment cannot silence AGC-REV-001. A record that names an agent by name covers it only while no
  other agent has that name.
- Feature: with `--base`, a change to a review record is listed in the text, Markdown and JSON
  reports with its date, owner, the capabilities it approves (and what it approved before) and
  what the agent can do now without asking, marking what the record does not approve and what is
  only possible. A renewal reads as an approval of access, not a
  one-line date change. The review file is read from the change. The review policy in
  `.agc.yaml` is read from the base, like the rest of the gate.
- API: `ScanOptions.now` sets the clock for review dates, `ScanResult.reviews` lists the records
  read, and `ScanDiff.reviews` lists the records a change added, removed or edited.

## 1.4.0 — 2026-11-20

### Agent Map

- Feature: `get_agent_topology`, a thirteenth read-only operation, and a Topology view in the
  viewer. It draws the agents you may see as one graph: the MCP servers, cloud identities,
  caller principals, credentials, resources and network segments that two or more of them
  share; the delegations, handoffs, dependencies and allowed recipients that link one agent to
  another (live tasks only); and for each agent an isolation summary (coverage-aware, so an
  incomplete collection reads unknown, never dedicated or none), what it may send out, its
  declared network isolation, and its last change between the two retained snapshots. Agents
  removed since the previous snapshot are listed. Filters choose what is drawn and never turn
  a shared item into a dedicated one. One IAM ARN used from several sources is one hub. A fleet
  too large for the full answer gets every status and count without the detail lists
  (`compact: true`). Everything is declared evidence, not observed traffic.
- Feature: the five network fields of manifest v4 are map properties of a deployment
  (`network_status`, `network_segment`, `network_egress`, `network_egress_targets`,
  `sandbox_kind`). A malformed stored declaration reads as unknown. Changes appear in
  `get_changes` under `bindings`.
- Refactor: `get_changes` categories come from one shared function, also used by the topology;
  its output is unchanged.

### Host manifest v4

- Feature: `agent-guard-inventory-manifest-v4.schema.json` is manifest v3 plus a required
  `networkIsolation` list. Each entry has `deploymentId`, `segmentId` (opaque, or `null` for no
  shared segment), `egress` (`none` | `allowlist` | `open`), `egressTargets` (opaque refs, `[]`
  unless `allowlist`, at most 32) and `sandbox` (`none` | `process` | `container` | `vm`); at
  most one entry per deployment and 1,000 in total; `[]` declares nothing. It is a generated
  `$ref` envelope over v3 with a drift test, and the v2 snapshot schema accepts it.
- Executor: validates v4 and composes it like v3 into a v2 snapshot.
- Cartography collector: sets `network_status` on every deployment of a v4 manifest
  (`declared` or `not_declared`; absent before v4, which reads unknown) and the four network
  fields on declared ones. Moving a host from v3 to v4 at the same ledger revision is accepted;
  going back from v4 to v3 is refused as `MANIFEST_SCHEMA_ROLLBACK`.

### Check

- `@shieldaai/agent-guard-check` reads manifest v4 files like v3; network isolation adds no
  finding.

## 1.3.1 — 2026-11-18

### Check

- Fix (twelfth review): a deciding hook whose output is decoded, or printed from a file next to
  it, may approve; `Bash(name*)` matches other programs; a single `&` and `<( )` split exact
  rules; scripts outside the project and more pass-through forms are not project code;
  `additionalDirectories` and Gemini `includeDirectories` outside the project are private data;
  settings and loaders moved through `$GITHUB_ENV` / `$GITHUB_PATH`, job and workflow
  `defaults.run.shell`, commands built by expressions, local JavaScript and Docker actions and
  the Claude Agent SDK are followed; MCP findings are keyed on what a server runs, so `--base`
  sees a swapped program; edit rules aimed at agent settings by pattern are AGC-PER-002 (every
  file: medium); the Claude Code VS Code extension's bypass settings and Zed `tool_permissions`
  are read. Harmless exact commands (version checks, listings, workspace scripts) are no longer
  reported. Hooks with the same command are judged once.
- Fix (eleventh review, root causes): exact Bash rules are split like a shell and options that
  run programs are read; network-scope commands bring in untrusted input. Hooks fail closed: a
  deciding hook whose decision cannot be read may approve, and files it prints and modules it
  imports are read. MCP servers that start a network tool or inline code are AGC-PERM-003. Unknown
  Claude Code and Codex flags, Codex `-s`/`-c`/`CODEX_HOME` forms, earlier steps that write agent
  settings, remote actions and reusable workflows handed agent flags or model keys, decoded text
  piped into a shell, `npm test`/lifecycle scripts, Taskfile, Dockerfile, aliases and symlinks
  are followed or made unknown reach. `claude-code-base-action` is not write-gated. AGC-COV-001
  is high when an agent can both run code and send data out without approval and nothing checks
  it. VS Code settings in workspace files and dev containers, URL and edit auto-approve, Cursor
  hooks, more settings `env` loaders, unknown gh-aw keys, gh-aw write tokens and risky safe
  outputs on outsider events, OpenCode `lsp` and provider URLs, and Codex and Gemini telemetry
  are read. Script chains, gh-aw import graphs, reusable-workflow call graphs and long quoted
  rules are scanned in linear time.
- Fix (tenth review): gh-aw lock tool lists are read as Claude Code reads them (spaces,
  several arguments), and an agent CLI other than the source's engine is a hand edit. A Bash
  rule for a repository script that runs its arguments as a command, and prefix rules for
  `make`, `go`, `cargo` and `just`, allow any command. `CLAUDE_CONFIG_DIR` and `HOME` redirects
  in workflows are followed.
- Fix (ninth review): files run by an interpreter (`python3 ci/x.py`, `node`, `ruby`, `uv run
python`) are read for a process that starts an agent; `"${ARGS[@]}"` counts as unresolved
  flags; `find -exec` commands are read; a `./` path that climbs out of the project is not a
  project script.
- Fix (eighth review): fail-closed defaults. A Bash rule is narrower than "any network command"
  only when it matches a known command shape: unknown programs, wrappers (`sudo`, `timeout`,
  `xargs`), wildcards inside the command and prefix rules for commands whose options run programs
  (`git:*`, `find:*`, `rg:*`) are AGC-PERM-003, in every agent that uses Claude's rule syntax.
  Hooks are judged like commands (scripts from the repository read); a hook that approves tool
  calls is AGC-PERM-001 and never a runtime check; HTTP hooks and helper commands are covered.
  Build-output folder names are skipped only outside configuration folders, and configuration in
  a skipped folder is reported. Workflow scripts: shell keywords, `eval`, repository scripts,
  `npm run` and `make` targets, `docker run`, other agent CLIs and actions, case-insensitive
  inputs, expressions inside flags and agents named where the scan cannot follow. gh-aw locks are
  checked against front matter only. Unknown MCP servers that run without asking, enabled
  plugins from outside the repository, unmodelled agent files (Cursor hooks, Roo, Continue, ...),
  VS Code, Zed and Aider auto-approve, Gemini hooks and discovery commands, Codex `notify`,
  OpenCode plugins and settings `env` loaders are reported. Secrets passed through files,
  `$GITHUB_OUTPUT`, cloud-credential actions and checkout tokens reach the agent. Front matter
  with spaces after `---` and space-separated tool lists are read. Quadratic paths removed.
- Fix (seventh review): configuration folders are walked first and a folder reached through
  links more than 4 times stops the walk, which is reported at high. Agent CLIs in `run:` scripts
  are found by splitting the script into commands (quotes, wrappers, `bash -c`, `$(...)`, shell
  variables), so quoting or an env prefix no longer hides one and `claude --version` is no
  longer an agent; unresolved arguments and expressions in `claude_args` are unknown reach.
  Agent actions are matched under any owner, composite actions are read step by step, list
  flags are variadic, and CLI paths follow `working-directory`. Secrets are found in every
  expression form, in prompts and through `$GITHUB_ENV`; a harness variable is excluded only
  for a secret named for a model or telemetry provider. Reusable workflows take their callers'
  triggers. gh-aw lock files are checked against their source (triggers, agent flags, and
  gh-aw's own `frontmatter_hash`). Files that cannot be parsed and rules that fail are findings,
  not only warnings. `apiKeyHelper`, `statusLine` and the other helper commands, and hooks in
  skill, command and subagent front matter, are judged as hooks. Model endpoints in workflows
  and gh-aw engines are high unless they name a provider's host. Duplicate step names no longer
  merge agents, and a duplicate finding keeps the higher severity. A Codex `profile` selects its
  sandbox; `gh api` prefix rules are not read-only.
- Fix: AGC-COV-001 counts a runtime check only for the calls it sees. A `PreToolUse` hook on
  `Bash` no longer hides an unchecked `WebFetch` or MCP server, and Agent Guard or an MCP gateway
  reached as an MCP server covers only the calls made through that server. The text report says
  what each check sees, for example `pre-tool-hook (Bash)`.
- Fix: Claude Code permission modes `auto` (no person approves; its safety review counts as a
  runtime check), `dontAsk` and `manual` are modelled; `acceptEdits`
  also runs `mkdir`, `touch`, `mv` and `cp` without asking; a subagent in `auto` mode is reported
  by AGC-PERM-006 (medium). An unknown mode, Codex `sandbox_mode` or `approval_policy`, or Gemini
  approval mode is judged at its widest instead of being ignored.
- Add: AGC-CFG-001 (info, low confidence) reports a setting the scanner does not model, with
  what it assumed: unknown modes, Cursor CLI tokens, OpenCode actions, OpenCode files with no
  permission settings, and Claude Code's Bash sandbox.
- Add: `mcp_servers` in `.agc.yaml` declares what an MCP server can do, keyed by what runs
  (package, image, host or catalog ID), never by the config name a change chooses. With `--base`
  it is read from the base commit.
- Fix: a package or image is identified only when the command has exactly the expected shape
  (runner, harmless flags, package and its arguments; or `docker run` with known flags and the
  image). `-p`, `--call`, other runner flags, shell lines with a second command,
  `--entrypoint`, `--env-file`, unknown docker flags, loader environment variables
  (`NODE_OPTIONS`, `npm_config_*`, `LD_PRELOAD`, ...) and command-plus-URL servers stay unknown.
- Add: AGC-CFG-002 reports an agent configuration file the scan could not read (too large, a
  link out of the repository, unparseable front matter): high for settings and
  agent definitions (subagents, Copilot, OpenCode and gh-aw agents in Markdown), so padding one
  past 1 MiB fails the gate instead of hiding it; medium for instruction files.
- Fix: identification also gives up for project dependencies, repository package sources
  (`.npmrc`, `uv.toml`, ...), `envFile`, docker mounts, and package specs that fetch from outside
  the registry. AGC-POL-001 matches on the same identity and never on the config name;
  AGC-SUP-001 checks every package a command fetches and reports shell lines it cannot read.
- Add: the MCP catalog knows 24 more servers, 44 in all (search, browsers, documentation,
  databases, Kubernetes and SaaS accounts such as Zapier, Asana, Figma and PostHog).
- Fix: hook matchers are never run. Coverage is read from the matcher's alternatives (exact tool
  names, name prefixes, every tool); a matcher must compile and be at most 512 characters.
  `disableAllHooks` and managed `allowManagedHooksOnly` are honoured.
- Fix: Claude Code's Bash sandbox: sandboxed Bash runs and writes without asking unless
  `autoAllowBashIfSandboxed` is false; the sandbox never lowers network reach.
- Fix: AGC-TXT-001 no longer reports the zero-width joiner inside an emoji, and AGC-TXT-002 no
  longer reports a phrase quoted as an example of an attack, or "do not tell the user to ...".
- Add: GitHub Agentic Workflows (`.github/workflows/*.md` with `on:`) are read as unattended
  agents, with their triggers, tools (imported lists joined), safe outputs (a runtime check for
  what they post unless threat detection is off), secrets, tokens, permissions, MCP servers
  (including containers) and repository imports three levels deep. A custom engine, an import
  that cannot be read, an unmodelled tool or custom safe-output jobs are unknown reach.
- Fix (sixth review): gh-aw lock files are read for agent actions gh-aw never generates, and
  `--base` reports a lock changed apart from its source; gh-aw `jobs`/`steps` that start an
  agent, `sandbox: { agent: false }` and `secrets` are modelled; agent actions match any case and
  sub-path (`base-action`), and local actions that wrap an agent are agents; harness credentials
  must carry a model key to be excluded; `--mcp-config` paths are read; skill and command
  `allowed-tools` are allow rules; case variants and case collisions are reported; a marketplace
  plugin in a skipped folder, a Codex provider endpoint and NODE_OPTIONS in settings are high;
  pinned remote gh-aw imports are medium; Gemini runs without `-p` are detected. Robustness:
  folder-link loops are walked once, the walk reports folders deeper than 32 levels (medium),
  git link targets are read by bytes, nested links in git trees are followed, and very large
  repositories no longer crash the walk.
- Fix (fifth review): links are resolved as the operating system resolves them and folder links
  inside the repository are walked at their path; a gh-aw header hides nothing unless the file is
  a `.lock.yml` with a gh-aw source beside it; linked agent definitions are kept; harness secrets
  are matched by exact name; settings files and gh-aw imports outside the repository (or at a
  moving ref) are high; Gemini through `npx` and `run-gemini-cli`, mixed-case action names, and
  model endpoints in action settings are read; an endpoint redirect in the repository's Claude
  Code settings is high.
- Fix (fourth review): fail closed on what is not read. A configuration file committed as a link
  is read through a target inside the repository and otherwise reported; front matter that is not
  valid YAML, a settings file that cannot be read, and a walk that stopped early are reported as
  AGC-CFG-002 and counted as unknown reach. `claude-code-action` `settings` as a file, a mapping or
  JSONC, and `--settings`, are read. Runners and `docker` from the repository, `cwd`, docker daemon
  variables and nested package sources stop identification, and package sources are scoped to
  their ecosystem and folder (an `.npmrc` with only `engine-strict` changes nothing). Unidentified
  servers may also write and run code (unknown). gh-aw container servers with an entrypoint,
  mounts or arguments, engine `args`, body imports, nested imports relative to their file, engine
  environment secrets and an open network are modelled. Copilot CLI and Gemini CLI steps, and
  gh-aw lock files with no source, are agents. Auto mode's review covers only the calls the mode
  lets through, and project `defaultMode: auto` is AGC-PERM-001 (medium). AGC-POL-001 can allow a
  remote server by host. Model endpoints and proxies in workflow `env` and Codex providers are
  reported.
- Fix: `codex-args` given as a JSON array or YAML list is read, and the wider Codex sandbox wins
  when flags and inputs disagree. `claude-code-action`'s inline `settings` and
  `claude -p --permission-mode acceptEdits|auto` are read. Wide edit patterns (`Edit(**/*.md)`,
  `Edit(/**)`) and an allow-all rule count as changing the agent itself. YAML merge keys in
  frontmatter are read. A model endpoint override (`ANTHROPIC_BASE_URL`) is reported.
- Fix: `openai/codex-action` steps and `codex exec` run commands without asking inside their
  sandbox; they were reported with no capabilities. A workflow agent with a GitHub token and a
  shell has unknown untrusted input. VS Code and Cursor agents have their built-in terminal,
  fetch and edits. An agent that can edit any file or run any command can change itself.
- Add: the Sentry CLI server (`sentry mcp`) is in the catalog, and Sentry can write.
- Add: the benchmark measures recall against independent labels for 8 public repositories
  (`bench/recall-labels.json`): 97% of agents found, 80% of labelled capabilities reported.
- Note: the inventory's `runtimeChecks` may now list `safe-outputs`, and lists every `PreToolUse` hook, not only those that
  see Bash. Which calls each check sees is in the JSON report (`mediators`), and AGC-COV-001
  uses it.
- Add: OpenCode (`opencode.json`, agent overrides and `.opencode/agent/*.md`), the Cursor CLI
  (`.cursor/cli.json`), GitHub Copilot custom agents (`.github/agents/*.md`, cloud or
  `target: vscode`), Kiro (`.kiro/settings/mcp.json`), Claude Code plugin folders and Agent
  Plugins are read as agents. A plugin never takes a project's `.mcp.json` away from Claude Code.
  Repository folders named `~` or `<managed>` are never read as user or managed settings, and a
  FIFO named by a plugin manifest cannot block the scan. Copilot, Cursor, Windsurf and Kiro instruction files
  feed the text rules.
- Add: `--include-user` merges your own settings (`~/.claude`, `~/.claude.json`, `~/.codex`,
  `~/.gemini`, managed settings and servers) in Claude Code's order. Local runs only: refused
  when `CI` is set, with `--fix` and with `--write-baseline`.
- Add: `schemas/agent-guard-check-inventory-v1.schema.json` publishes the `--format inventory`
  output, and a test keeps them in step.

## 1.3.0 — 2026-11-16

### Core

- Add: `guard.describe()` lists registered tools, sorted by name, with fingerprint, approval and
  declared safety labels (`readsUntrusted`, `untrustedContext`, `sendsExternal`; `null` when not
  declared). Read-only, frozen and free of task, argument and secret data. It lets a static reviewer
  compare a core-only host with its agents' configuration.

### Check (new package: `@shieldaai/agent-guard-check`)

A scanner for AI agent configuration in a repository. By default it reads files only: it never
runs repository code, never starts an MCP server and makes no network calls. It works with or
without Agent Guard.

- Feature: builds each agent's authority (reads private data, reads untrusted input, writes,
  runs code, sends data out, spends money, changes itself) from Claude Code settings, `.mcp.json`,
  subagents (`permissionMode`, `disallowedTools`, inline `mcpServers`), skills and hooks, plugin
  marketplaces, OpenAI Codex `.codex/config.toml`, Gemini CLI `.gemini/settings.json`, VS Code and
  Cursor MCP config, and GitHub workflow steps that run `claude-code-action`, `codex-action`,
  `claude -p` or `codex exec`. Each capability is `no`, `unknown`, with approval or without
  approval, and cites the granting file and line.
- Feature: 46 rules (`AGC-*`) mapped to OWASP ASI01–ASI10. 34 run on repository files, including
  the lethal trifecta, unpinned MCP packages and plugins, agents triggered by outsiders while
  holding a write token, unattended agents with write access, long-lived cloud keys, subagents
  broader than their parent, and hardcoded credentials (masked in output).
- Feature: Agent Guard records. `guard.describe()` output, executor inventory snapshots and host
  manifests add 8 rules (`AGC-AGX-*`) that mirror Agent Map's dangerous-three verdicts.
- Feature: live evidence. `--live` or `--agent-map-url` queries a running Agent Map read-only and
  adds 4 rules (`AGC-DRF-*`) on undeclared activity, unclaimed identities, exposed agents and
  stale inventory. The token comes from the environment only.
- Feature: policy as code in `.agc.yaml` (approved MCP servers and hosts, forbidden capability
  combinations).
- Feature: `--fix` and `--fix-dry-run` apply safe fixes, each verified by scanning again.
- Feature: `--base <ref>` reports only capabilities that grew and findings that are new.
- Feature: text, JSON, SARIF 2.1.0, Markdown and inventory output; `--import-sarif` merges other
  scanners' findings; reasoned ignores, severity overrides, inline `agc-ignore` comments and
  baselines.
- Feature: a GitHub Action (`packages/check/action`), a read-only MCP server
  (`agent-guard-check-mcp`), a Claude Code skill, a pre-commit hook and a container image.
- Tests: a labeled benchmark of 123 cases (each rule flags at least one configuration and stays
  quiet on a look-alike) gates the build; 32 public repositories at pinned commits reproduce the
  hand-reviewed findings.

Changes from the first merged version (pull request 70), after two pre-release reviews:

- Security: with `--base`, `.agc.yaml` and an in-repository baseline are read from the base
  commit, so a pull request can no longer lower its own gate (`fail_on: none`, severity
  overrides, ignores or new baseline entries).
- Security: `agent_map.token_env` must end in `AGENT_MAP_TOKEN`; before, a repository's
  `.agc.yaml` could name any secret to send to the Agent Map URL it chose.
- Security: `.agc.yaml` and files named on the command line are opened without following links,
  with the size checked first; a parse error prints one line, never the file.
- Security: the GitHub Action runs the scanner outside the checkout with the public registry, so
  a committed `node_modules` or `.npmrc` cannot replace it; its text report runs with workflow
  commands stopped.
- Security: text output keeps names from repository files on one line (no injected workflow
  commands); Markdown also neutralises line breaks, mentions and links. Existing report and
  baseline files are made owner-only too.
- Fix: `--base` reports a finding whose severity rose, and a new finding silenced inline in the
  same change.
- Fix: Claude and Codex commands split over lines or started through `npx`; Codex
  `-s danger-full-access` and `-c sandbox_mode=...`; `${{ env.X }}` in agent flags; a
  `github_token` from a secret counted as write access; `pull_request_target` checkouts of the
  merge ref or with `gh pr checkout`.
- Fix: an MCP package counts as pinned only at an exact version (`@1`, `@beta` and `>=1.0` do
  not), also behind `cmd /c`, `sh -c` and `npx.cmd`.
- Fix: AGC-PERM-006 compares a subagent with its own project's settings, not a sibling
  package's; `find`, `awk`, `sed` and `xargs` count as running code, `cp`/`mv`/`tee` as writing,
  `git clone`/`pull`/`fetch` as untrusted input; only a PreToolUse hook that sees Bash, and not
  this scanner's own MCP server, counts as a runtime check.

### Release

- Every published package now runs the release check before `npm publish` (`prepublishOnly`);
  `npm run test:pack` fails if one does not. The lockfile now records the check package's
  version and both of its executables.

### Adapters

- Tests: every adapter (Anthropic, OpenAI Responses, OpenAI Chat Completions, Gemini, Bedrock,
  Vercel AI SDK, OpenAI Agents SDK, LangChain, MCP server) now gets the same blocked calls: a
  denied call, a call waiting for approval, a rejected wait and a timed-out wait. Each test
  checks that the tool handler never ran, that the model is told the call was blocked (never
  `ok`), and that the format's error flag is set where it has one. Matching an SDK's types
  proves a result's shape, not its meaning. No change to published code.

## 1.2.0 — 2026-11-15

A new package, `@shieldaai/agent-guard-adapters`, connects the guard to model providers and
agent frameworks. The other five packages are unchanged apart from their version. The
[release notes](docs/releases/1.2.0.md) are the short version.

### Adapters (new package: `@shieldaai/agent-guard-adapters`)

Connect the guard to model providers and agent frameworks without writing the dispatcher
yourself. No third-party runtime dependencies; framework factories are passed in.

- Feature: `createDispatcher()` routes every model tool call through prepare, an optional
  wait for a person, and execute, and returns a plain outcome (`ok`, `denied`,
  `waiting_for_approval`, `failed`) with a model-facing message for every guard code. Works
  with the core guard, the durable executor (`executorBackend`) and the executor's task client
  (`executorClientBackend`).
- Feature: `ApprovalQueue`: pending actions for reviewers, `approve()`, `reject()`,
  `complete()` with an externally issued approval, `waitFor()`, and an optional
  `waitForApproval` mode for frameworks whose tool function must return the final result.
  Each task has its own share of a shared queue (`maxPendingPerTask`); actions of a revoked
  or expired task, or older than `maxWaitMs`, are dropped; a refused approval keeps the
  action waiting (`APPROVAL_NOT_ACCEPTED`).
- Feature: host errors (a broken backend, a network failure to a remote executor) reach the
  dispatcher's `onHostError` hook; the model gets `HOST_ERROR` with no detail, and the other
  calls of the turn keep their results. A remote execute that fails with a transport or
  response code is reported as `failed` (effect unknown), never `denied`.
- Feature: provider adapters for the Anthropic Messages API, OpenAI Responses and Chat
  Completions (and compatible APIs), Google Gemini and Amazon Bedrock Converse.
- Feature: framework adapters for the Vercel AI SDK, the OpenAI Agents SDK, LangChain.js and
  LangGraph.js, and `registerMcpServerTools()` / `mcpServerTools()` to offer guarded tools to
  any MCP client (Claude Code, Claude Desktop, Cursor, VS Code).
- Feature: `toolSpecs()` reads tool specs from the guard's approved registrations, so the
  model never sees a changed definition before review; `registerApprovedTools()` with
  optional fingerprint pins; `taskBudget()`.
- Feature: `jsonSchemaParser()` and `validateJsonSchema()` enforce the tool's JSON Schema as its
  `parse` (unsupported keywords, and patterns with nested quantifiers, fail when the parser is
  built; work on oversized arrays and strings is bounded); `standardSchemaParser()` for
  Zod, Valibot and ArkType.
- Feature: composable policies: `combinePolicies`, `denyTools`, `requireApprovalForTools`,
  `requireApprovalForExternal`, `requireApprovalAfterUntrusted`, `withinHours`, `denyWhen`,
  `requireApprovalWhen`.
- Feature: `RateLimiter`: per-tool limits shared across tasks (per tenant, principal or
  globally) in a sliding window; calls are counted when dispatched, so denials never use
  the allowance.
- Feature: `defineTool()` types a tool's arguments from its `parse`; `jsonSchemaParser` and
  `standardSchemaParser` take the parsed type as a type parameter.
- Feature: decision hooks: `openTelemetryDecisionHook` (counter and span events, no
  OpenTelemetry dependency), `jsonLinesDecisionLogger`, `DecisionStats`, `combineDecisionHooks`.
- Feature: the `agent-guard-explain` command explains any guard or adapter code.

### Repository

- Examples: `examples/model-adapters.mjs` (one model turn in five provider formats) and
  `examples/mcp-guarded-server.mjs` (a stdio MCP server with guarded tools, with an offline
  `--self-test`).
- Docs: [Connect your model or framework](docs/guides/integrations.md).
- Scripts: `scripts/verify-adapters-real-packages.mjs`, run by hand, runs the framework
  adapters against the real framework packages and type-checks the provider adapters against
  the official SDKs.
- Release: the build, pack, package checks and `docs/releasing.md` include the sixth package.

## 1.1.1 — 2026-11-13

A documentation-only patch. No code, type or behavior changes from 1.1.0. The
[release notes](docs/releases/1.1.1.md) are the short version.

### Core

- Docs (core): the npm README now opens with the problem Agent Guard addresses and links to
  the OWASP Top 10 for Agentic Applications mapping before the install command and example.
- Docs (core): the package `description` now leads with the outcome: limiting what a misled
  AI agent can do.

### Repository

- Docs: the README's problem section points to the OWASP mapping table.
- Docs: `docs/releasing.md` says to publish from a full clone, because npm does not record
  `gitHead` from a `git worktree` checkout. `@shieldaai/agent-guard@1.1.0` was published
  without `gitHead` for this reason.
- Security (Cartography integration, not published to npm): the locked `dnspython` moves
  from 2.9.1 to 2.9.2 for [GHSA-vvf4-9x63-8xvv](https://github.com/rthalley/dnspython/security/advisories/GHSA-vvf4-9x63-8xvv),
  excessive memory and CPU use when parsing a crafted WKS record in zone-file text.

## 1.1.0 — 2026-11-13

Reviewers can now see what changed in a tool definition before they approve it again
([issue 57](https://github.com/ShieldaAI/agent-guard/issues/57)). Nothing in the 1.0 API
changes or is removed, and no existing check is weaker. The
[release notes](docs/releases/1.1.0.md) are the short version.

### Core

- Add (core): `toolChanges(name)` compares a tool's current registration with the last
  approved definition of that name and returns one entry per changed JSON path (`path` as
  a JSON Pointer, `kind` added, removed or changed, `before`, `after`). Schemas are
  compared structurally. `status` is `first_approval`, `unchanged`, `changed` or
  `unavailable`. The comparison covers the fingerprinted fields, never what the tool's
  code does.
- Add (core): `approveTool()` keeps the approved definition. `unapproveTool()` keeps it;
  `unregisterTool()` removes it. A definition larger than the new
  `limits.maxToolDefinitionBytes` (64 KiB by default, 1 KiB to 1 MiB) is approved by
  fingerprint only, as before, and `toolChanges()` reports `unavailable` instead of a diff.
- Add (core): heuristic `hints` on each change (`INSTRUCTION_TEXT`, `HIDDEN_CHARACTERS`,
  `SCHEMA_FIELD_ADDED`, `SCHEMA_LOOSENED`, `FLAG_LOOSENED`). They are for the human
  reviewer and never block anything.
- Add (core): `approveTool(name, fingerprint, { reviewedAgainst })` refuses with
  `TOOL_CHANGED` when the last approved fingerprint is not the one the reviewer's
  comparison showed (`null` for a first approval).
- Add (core): `diffToolDefinitions(before, after)` and the types `ToolChanges`,
  `ToolChange`, `ToolChangeHint`, `ToolDefinitionDiff` and `ApproveToolOptions`.

### MCP

- Add (mcp): `ManagedMcpConnection.operationChanges(name)` (also on
  `VerifiedMcpHttpSession`) shows what the server changed in one operation since it was
  last approved on the guard, after a `refresh()` or on a new connection, with
  `descriptorDigest`, `approvedDescriptorDigest`, descriptor `changes` and the host's
  `bindingChanges` (binding flags and connection identity). The connection session and
  epoch are not reported as changes.
- Change (mcp): the `guard` option may also provide `toolChanges` (type `McpGuard`). A
  guard with only `registerTool` still works; `operationChanges()` then throws
  `INVALID_CONFIGURATION`.

### Executor

- Add (executor): `approveTool()` records the approved definition in the ledger, with the
  approval time, an optional `approverId` and the approved fingerprint it replaced.
  `toolChanges(name)` compares against that record, so a tool that changed across a
  restart shows its diff; `toolChanges(name).approval` returns the recorded approval.
- Add (executor): option `maxToolDefinitionBytes` (64 KiB by default). Kept definitions
  together use at most an eighth of `maxLedgerBytes`. A definition over either bound, or
  one approved at the ledger's soft limit, is approved by fingerprint only (`APPROVED_DEFINITION_NOT_KEPT`); approval is never refused for that reason.
- Ledger: the record is an additive optional field. `formatVersion` stays 1, a ledger
  written by 1.0.0 opens unchanged (its tools report `first_approval` until approved once),
  and 1.0.0 still opens a 1.1.0 ledger. A committed 1.0.0 fixture covers the first; the
  second was checked once against the published 1.0.0 package and has no automated test.

### Scenarios

- Change (scenarios): catalog 1.4.0 extends S06 with the definition diff and an approval
  against a comparison that was not shown. `GuardLike` gains an optional `toolChanges`;
  the new checks run only for adapters that provide it.

### Agent Ops (source only)

- Add: Maintenance shows a **Tool definition** panel: what changed in the service's own
  tool since it was last approved, old and new value side by side, hints marked, all
  values shown as text. `GET /api/maintenance` adds `toolDefinition`. The service still
  approves its own tool at startup, now with `system:startup` recorded as approver.

## 1.0.0 — 2026-11-12

The first stable release. The last published version was `0.1.0-alpha.3`; this entry
covers everything since then, which is why it is long. The
[release notes](docs/releases/1.0.0.md) are the short version: what 1.0 contains, its
known limits and the upgrade steps from `0.1.0-alpha.3`.
The inventory observer and Agent Map remain experimental, and running the observer on
one logical CPU with 250 ms polling is not supported.

The entry is grouped by package. Within a group, removals and changes come first, then
additions, then fixes.

### Core

- Remove (core, executor): the root aliases the alphas exported for the internal SPI and
  for names that live on subpaths. Import `PolicyAdmission`, `assertActionAuthority`,
  `containsLiteralSecret`, `canonicalJson`, `digestJson` and `immutableJson` from
  `@shieldaai/agent-guard/internal`, and the sandbox, inventory, pilot and operator names
  from `@shieldaai/agent-guard-executor/sandbox`, `/inventory`, `/pilot` and `/ops`.

- Change (core): each check reuses per-task authority views built at task creation;
  `assertActionAuthority` (`/internal`) also accepts the precomputed form. Every public
  method and type is documented, and `GuardErrorCatalog` causes say what to do next.
- Change (core): `DELEGATION_DENIED` carries a `detail` naming the exceeded limit
  (`GRANT_`, `RECIPIENT_`, `CONTROL_PLANE_`, `BUDGET_` or `DEADLINE_EXCEEDS_PARENT`), and
  `EXECUTION_ABORTED` carries `EFFECT_COMMITTED` when the handler had finished.
- Change: the internal SPI moves to `@shieldaai/agent-guard/internal` (no semver
  guarantees): `PolicyAdmission`, `assertActionAuthority`, `containsLiteralSecret`,
  `AuthorityPhase`, `AuthorityState`, `canonicalJson`, `digestJson` and
  `immutableJson`. The root no longer exports them. First-party packages import from `/internal`. The root
  entry also exports `InvalidJsonError`.
- Add (core): `limits.maxJsonBytes` (64 KiB to 64 MiB, default 1 MiB) and
  `limits.maxJsonNodes` set the JSON size limits for arguments, results and tool metadata.
  A result over the limit still fails `RESULT_INVALID` and revokes the task.
- Add (core, executor, MCP; opt-in): an outside-content flag. Tools can declare
  `readsUntrusted`, `untrustedContext` (`allow` / `require_approval` / `deny`) and
  `sendsExternal` (`false` enforced); a resolver can add `untrusted: true` per call. A
  family that dispatches such a call is marked `untrusted` for good (persisted in the
  ledger). Then `require_approval` tools need a review, a pre-read approval fails with
  `APPROVAL_CONTEXT_CHANGED`, and `deny` tools fail with `UNTRUSTED_CONTEXT_DENIED`.
  `snapshot()`, policies and `onDecision` see the flag; MCP connections can be marked
  `readsUntrusted`. Defaults are unchanged (`allow`), and tools that set none of the
  labels keep their fingerprints.
- Add (core API shape for 1.0): `executeDetailed()` returns `{ value, charged,
actionId }`; `retireTask()` revokes and forgets a task, bounding memory and task IDs
  in long-running guards; `unapproveTool()` and `unregisterTool()`; an `onDecision`
  audit hook (identifiers only; it cannot change an outcome); `snapshot()` adds
  `budget` and `revoked`; a `limits` option for the previously fixed approval and
  policy bounds; and `monotonicClock`. The default clock stays `Date.now`.
- Add: an error catalog. `GuardErrorCatalog` documents every `GuardErrorCode` with its
  meaning, whether a retry is safe and the typical cause, and `docs/errors.md` is
  generated from it (a test fails on drift). Flattened adapter errors keep a safe
  uppercase adapter code as `GuardError.detail` and `cause.code`.
  `McpBoundaryError.code` is now typed as `McpBoundaryErrorCode`.
- Fix (core): arguments just under the JSON limit no longer fail `INVALID_JSON` after
  `resolve` and the policy have run.
- Fix (core): a clock failure after the handler ran reports `EXECUTION_ABORTED` and is
  audited as failed, not `CLOCK_INVALID` audited as denied.
- Fix: a call in flight no longer refuses `prepare()` or `approve()` with
  `CONCURRENCY_EXCEEDED`/`COST_BUDGET_EXCEEDED`, in core and in the durable
  executor. Transient capacity (concurrent calls, reserved cost) is enforced at
  dispatch; permanent capacity (calls, spent cost) still refuses preparation.
  `assertActionAuthority` gains an optional `phase` (default `dispatch`).

- Docs (core): examples for delegation and the `onDecision` log, and a note on the frozen,
  prototype-less values handlers receive. Examples no longer import deprecated root names.

### MCP adapter

- Change (mcp): a non-object argument value now fails with `ARGUMENTS_INVALID`, like a
  schema mismatch; `INVALID_ARGUMENTS` is removed. `REGISTRY_CHANGED` is new.
- Add (mcp): `McpBoundaryErrorCatalog` (meaning and next step for each code) and
  `limits.maxMessageBytes` (1 to 16 MiB) on managed connections.
- Add (mcp): each registration has a `descriptorDigest` that stays the same across
  connections and refreshes while the server advertises the same definition, so a host can
  store it at review and compare it before approving. `failureReason` gives the code behind
  the last quarantine. `VerifiedMcpHttpSession` exposes `skipped` and `failureReason` and
  accepts `readsUntrusted`; `registerMcpTool` passes the outside-content labels through.
- Report the installed package version from the MCP client (`agent-guard-mcp`) and
  the Agent Map MCP server instead of hard-coded strings.
- Fix (mcp): `limits.maxMessageBytes` also applies to a structured result checked against a
  tool's output schema. A malformed name advertised by the server is reported as
  `REGISTRY_REJECTED` or `SCHEMA_INVALID`, never `INVALID_CONFIGURATION`.
  `VerifiedMcpHttpSession.connect()` checks identity, bindings and limits before any network
  call. A server ID or binding name whose encoded operation name exceeds 4,096 characters is
  refused at construction. `failureReason` is `CONNECTION_UNAVAILABLE` after the transport
  closes unexpectedly.
- Fix (mcp): identifiers the inventory cannot report are refused at construction;
  `connect()` never reports a connection ready after its transport closed; a superseded
  `refresh()` always rejects with `CONNECTION_CHANGED`; the schema pattern budget is no
  longer module-global.
- Fix (mcp): a tool schema `pattern` using a regex modifier group such as `(?i:a)` could
  hang the host or skip the backtracking check; those forms are refused.
- Fix (mcp): a binding's explicit `readsUntrusted: false` is passed to the registration
  instead of being dropped. The tool fingerprint changes for bindings that set it.
- Fix: the MCP schema profile accepts common real-world tool schemas. The 2019-09 and
  2020-12 dialect URIs are accepted, `format` is an annotation, `uniqueItems` uses
  linear canonical-JSON equality, and `pattern` is accepted when its backtracking is
  bounded (with a per-value length cap and a per-validation work budget). A schema
  outside the profile now skips only that operation, listed in `connection.skipped`
  with its reason, instead of rejecting the server's whole registry.
- Fix: a managed MCP connection no longer quarantines on a failure that belongs to
  one call. An abort, deadline, timeout, JSON-RPC error reply, invalid or oversized
  result, resource mismatch or throwing `measureCost` now fails only that call.
  Connection-level failures still quarantine. The inbound message limit is now a
  sliding window (`maxMessages` per `messageWindowMs`, default 10,000 per 10 s)
  instead of a lifetime cap, and exceeding it quarantines instead of closing, so
  `refresh()` recovers. An oversized or malformed message that answers no pending
  call also quarantines instead of closing. A reflected protected value still
  closes the connection.
- Docs (mcp, core): record `descriptorDigest` per server, not per remote name alone; a
  handler aborted before its effect must throw, because returning normally under abort is
  reported as `EXECUTION_ABORTED` with detail `EFFECT_COMMITTED`.

### Executor

- Fix (executor): on Node 22, `agent-guard-ledger` and `agent-guard-pilot-review` no longer
  print Node's "SQLite is an experimental feature" warning between their error code and
  hint; other warnings are printed as before.
- Change (executor): a tool handler's error is always `TOOL_FAILED` (its safe code in
  `detail`) or `EXECUTION_ABORTED`; built-in tools keep their codes, and a memory version
  race settles `FAILED` at zero cost. Every public method throws only `GuardError` or
  `ExecutorError`; a store that cannot open says why in `detail` (`LOCKED`,
  `KEY_MISMATCH`, `CORRUPT`).
- Change (executor): the numbered task ID scheme that lifecycle export fences rely on is
  now a documented executor feature, `numberedTaskId()` and `NUMBERED_TASK_PREFIX`,
  instead of an Agent Ops convention string-built in two places. Persisted formats
  are unchanged.
- Change (executor exports): the root keeps the executor, task server and client,
  adapters, network and model tools. Sandbox, inventory (experimental), pilot review
  and operator tooling move to `/sandbox`, `/inventory`, `/pilot` and `/ops`, and
  Agent Ops building blocks to `/internal` (no semver). The root no longer
  exports the moved names (see the removal entry above).
  agent-map adds `/oidc` and `/identity-http`. Application sources now import
  packages by name only, and a test fails on any `dist/` import from `apps/`.
- Change: the durable executor task server returns HTTP statuses by kind (401, 403,
  404, 409, 429, 503, otherwise 400) instead of 400 for every denial, and the error
  body adds `retryable`. `ExecutorClient` accepts these statuses and exposes
  `retryable` on its errors. Older clients see the new statuses as
  `EXECUTOR_REQUEST_DENIED`; upgrade client and server together.
- Add (executor): `DurableExecutor.knowsToken()`; the `AuditEvent` type is exported.
- Add (executor): `unregisterTool`, `unapproveTool` and `maxApprovalsPerAction`.
  Admission and dispatch are one commit.
- Add (executor): `preparedAction(actionId)` and `POST /v1/admin/action` return the stored
  tool, arguments, resource, digest and status of an action, so a review screen shows what
  an action ID denotes from the ledger rather than from the party asking for approval.
- Add (executor): `loadInventoryManifestFile(path)` on the `/inventory` subpath loads a
  reviewed host manifest from a private file (owner-only, read once at startup, POSIX
  only), so declaring an agent is a file change and a restart. See
  [declare agents from a file](docs/guides/agent-cartography.md#declare-agents-from-a-file).
- Add (executor ledger format): ledgers carry an explicit `formatVersion` and a
  `features` list, kept current at each commit. A migration registry brings older
  layouts forward at open, inside the exclusive startup transaction, so the witness
  and mirror update in the same commit. A newer layout is refused unchanged
  (`STORE_FORMAT_UNSUPPORTED`). `executor.ledgerFormat()` and Agent Ops `check`
  report the format. The optional ledger fields are now real types instead of casts.
  Committed fixture ledgers written by `0.1.0-alpha.3`, `0.1.0` and the pre-format
  0.2 build (plain and witnessed) must open, keep counters, receipts and tokens, and
  still reconcile an uncertain effect. Policy: 1.x opens every ledger from
  `0.1.0-alpha.3` on; downgrade is not supported.
- Add whole-family retirement and encrypted archival, scoped execution listing,
  exact ID tombstones and crash-safe archival receipt discovery.
- Add offline, retryable ledger key rotation with independent rollback witnesses
  and a protected multi-key ring.
- Add managed offline key escrow, authenticated complete backups, active-key
  retirement and schema-3 current-state repair without witness rollback.
- Fix (executor): `revokeTask()` whose ledger write fails throws `OPERATION_FAILED` with
  `detail: 'REVOCATION_NOT_DURABLE'`; the executor records the revocation with its next
  successful ledger write and tries again in `close()`. `POST /v1/admin/revoke` answers 503
  with `"retryable": true` and that `detail` instead of 400 `REQUEST_INVALID`. Before, a
  restart silently undid such a revocation even when later writes succeeded.
- Fix (executor): an error thrown by a host callback inside a built-in tool (model
  `complete`, outbound `credential`, sandbox `onResult`, artifact broker `clock`) is always
  `TOOL_FAILED` with the error's code as `detail`; it can no longer surface as an executor
  decision such as `TASK_REVOKED`.
- Fix (executor): the task server checks rate limits before the ledger is read, so a
  credential over its limit costs no ledger read; requests refused for a limit or a bad
  token no longer count against `requestsPerMinute`. `registerTool()` for a tool the ledger
  already records unchanged is no longer refused at the soft limit, and the first such
  registration after a start writes nothing. `unapproveTool()` and `unregisterTool()` may
  use the ledger reserve, like `revokeTask()`.
- Fix (executor): the ledger reserves headroom so revoke, cancel, settlement and
  reconcile always commit (growth stops at a soft limit); receipts, stubs and recent
  events are retained per tenant, so one tenant cannot evict another's; `reconcile`
  accepts an action stranded in flight.
- Fix (executor sandbox): the sandbox, artifact receipts, build policy and the
  private-file adapter share one path rule (240 UTF-8 bytes, NFC, 256 paths); the archive
  reader carries long names; sandbox failures are coded and keep the original error;
  stream receipts sign the exact bytes written.
- Fix (executor ledger tools): errors keep the original cause with a safe `detail`;
  failed backup, restore and repair steps clean up and can be retried; custody and
  recovery validate the store shape; both CLIs print the code, then a plain hint.
- Fix (executor): ledger and archive decryption pin the AES-GCM nonce and tag lengths. Node
  22 and 24 accepted a truncated authentication tag; Node 26 already refused it.
- Fix (executor): memory written by a family that read outside content is marked
  `untrusted`, and reading it marks the reader's family, so `untrustedContext` rules follow
  content through governed memory. `importMemory` accepts `untrusted: true`.
- Fix (executor): an action pruned while its policy evaluation was pending failed with a
  raw `TypeError`; it now fails with `INVALID_PREPARED`.
- Fix (executor): the `host-mcp` inventory profile rejected every schema-2 host snapshot
  (outside-content labels in use, or a v3 manifest).
- Fix (executor): a sandbox command that exits non-zero returns its exit code and output
  instead of failing the export step, which left the action `UNKNOWN`.
- Fix (executor task server): tokens are authenticated before they are counted, so unknown
  tokens no longer spend the shared request window; administration routes keep reserved
  in-flight slots and are not counted in the server-wide window, so `revoke` stays reachable
  at the limit.
- Fix (executor): a task whose provenance or ancestry would pass the bounds that
  authentication and revocation rely on is refused at creation; a clock failure after an
  effect settled reports `EXECUTION_ABORTED` with `EFFECT_COMMITTED`; `audit()` no longer
  throws when the event ring exceeds 1 MiB; `ACTION_APPROVAL_LIMIT` and `numberedTaskId`'s
  `INVALID_INPUT` are `GuardError`s.
- Fix (executor): archived task families no longer leave token hashes in memory; an
  unknown maintenance CLI flag reports `MAINTENANCE_ARGUMENT_INVALID`.
- Fix (executor): an operator can accept a bounded backward clock step once at
  startup (`acceptClockSkewMs`, Agent Ops `--accept-clock-skew`), recorded as
  `CLOCK_SKEW_ACCEPTED`; without it a backward step still fails closed. A handler that
  completes after cancellation, revocation or its deadline now fails with
  `EXECUTION_ABORTED` and `detail: 'EFFECT_COMMITTED'`, so the caller knows the effect
  happened. The executor and the `/ops` key tools share one 1 MiB minimum ledger size.
- Fix (executor ledger): when `ROLLBACK` itself fails, the store keeps the original
  transaction error instead of replacing it, and closes so an unknown transaction
  state is never read.
- Fix (executor task server): bearer authentication uses an in-memory token index, so
  malformed and unknown tokens are refused without decrypting the ledger, and a valid
  one is found in O(1) instead of a scan over every task. The server adds
  per-credential and server-wide request rates, an in-flight request cap and a
  connection cap (`REQUEST_RATE_LIMITED`, 429).
- Fix: in the durable executor, one tenant's traffic no longer evicts another
  tenant's receipts or audit events. Settled receipts are kept per task family
  (`maxReceiptsPerFamily`, default 64), and shared caps prune the busiest family
  first. A pruned receipt now returns `status: 'PRUNED'` with its settled `outcome`
  instead of `INVALID_PREPARED`, which resolves the lost-response case. Audit
  events are kept per tenant (`maxRecentEventsPerTenant`, default 256; total
  still 1,000) and carry `tenantId` and a gap-detecting `sequence`.
  `audit({ tenantId })` filters by tenant. The ledger change is additive.
- Fix: in the durable executor, another task's or tenant's writes no longer make a
  call fail with `POLICY_STATE_CHANGED` while its policy is awaited. The check now
  compares the task's own policy inputs (counters, shared sensitivity), as the API
  contract describes, instead of the global ledger revision. Same-task changes are
  re-evaluated with the same bounded, turn-taking retry as core
  (`ExecutorOptions.maxPolicyAttempts`). Without a custom policy, no check applies.
- Fix: parallel calls on one task now work under a custom policy. A policy decision
  made on a snapshot that changed while it ran is re-evaluated on fresh state, not
  rejected outright. Re-evaluations on a task take turns, and the count is bounded by
  the new `maxPolicyAttempts` option (1–16, default 5; `1` keeps the old behaviour).
  The final checks and dispatch still run without an intervening await.
- Perf (executor ledger): `LedgerStore.read()` caches the last verified ciphertext and
  its decoded state. Each read still fetches the row and runs every witness and mirror
  check, but when the bytes are unchanged it returns a detached copy without
  decrypting, parsing or re-walking the ledger. With 1,000 tasks, read-bound calls
  such as `snapshot()` take about half the time (3.6 ms to 1.8 ms); prepare and
  execute are unchanged because the write path dominates. Read results stay fresh,
  detached and mutable as before, and `close()` drops the decrypted cache.

### Scenarios

- Change (scenarios): the source is split into one module per scenario group plus a runner;
  catalog 1.3.0 and the public API are unchanged.
- Add (scenarios): catalog 1.3.0 adds S13, sends after reading outside content, for
  thirteen scenarios and twenty-six cases. Adapters must support the outside-content
  labels to pass it.
- Fix: scenarios recognize rejections with the new `isGuardError()` brand check
  instead of `instanceof GuardError`, so a guard from a second installed copy of core
  passes conformance. `ConformanceReport.catalogVersion` is typed as `string`.

### Inventory observer (experimental)

- Add (inventory v2): `untrustedContextDefault`, the executor's mode for tools without
  their own, so readers can work out effective modes. The collector projects it onto
  `GuardTool`, and adds `delegated` and `derived` to `GuardTask` so a reader knows a
  parent or handoff source exists without learning which.
- Add (host manifest v3): `agent-guard-inventory-manifest-v3.schema.json` adds a
  required `directAccess` list, where the host declares paths that act without the
  guard (shell, database, network, SDK, MCP, other). Entries have opaque ids and target
  references, a 1,024-character description, and at most 32 per deployment (1,000 in
  total). `[]` is the host's claim of none, not a check. The executor validates v3 and
  composes it into a v2 snapshot. The collector projects `GuardDirectAccess` nodes and
  a per-deployment `direct_access_status`. The map adds
  `get_agent_access.outsideGuard.directAccess` with status `found`, `none_declared` or
  `unknown`; an older manifest always reads as `unknown`. The collector's authority
  hash now ignores neutral v2 fields, so moving a host to manifest v3 at the same
  ledger revision is not refused as `REVISION_CONTENT_CONFLICT`.
- Add (inventory schema v2): when outside-content labels are in use, executor
  snapshots use `agent-guard-inventory-v2.schema.json`, a `$ref` envelope over v1
  that adds `untrusted` on tasks and the three labels on tools. Otherwise the output
  stays byte-identical v1. The Cartography collector validates v2 (resolving v1
  locally, never over the network) and projects the fields onto `GuardTool` and
  `GuardTask`; a v1-only collector fails closed on v2. A generator and drift test
  keep the v2 file in sync with v1.
- Fix (executor inventory): listeners of one executor must agree on `reuseUnchangedMs`;
  the manifest file loader accepts the same 200,000-value manifests as the validator.
- Perf (inventory observer, experimental): an identical poll within
  `reuseUnchangedMs` (opt-in; off by default) returns the previous observation
  instead of re-projecting, keyed by the ledger ciphertext, registry, scope, profile
  and manifest. `host-mcp` is never reused. Unchanged 500-task polls drop from about
  4.2 ms to 0.25 ms; continuously written ledgers see no change.

### Agent Map and viewer (experimental)

- Change (agent map): `MAP_TIMEOUT` answers 504 when the whole request had arrived and the
  read (or, at sign-in, the identity provider) ran out of time. It stays 408 when the request
  itself did not arrive in time. The error body is unchanged.
- Change (agent map, viewer): the demo is built as its own file, `demo.js`, which the page
  fetches only when a reader opens the demo (`app.js` went from 897 KB to 815 KB). The
  directory given as `viewerDirectory` must now hold four files: `index.html`, `app.js`,
  `demo.js` and `app.css`.
- Change (viewer): the viewer's error class is `ViewerError`; it was named `ReferenceError`,
  like the JavaScript built-in.
- Fix (viewer): refreshing the agent list, or returning to a company page, keeps the
  current rows on screen while the same list is read again, so the page keeps its height,
  scroll position and keyboard focus. A different filter or page still shows "Loading
  agents…".
- Fix (viewer): after a company page returns and its session check passes, the scroll
  position is put back even in browsers that scroll to the refocused element (WebKit on
  Linux).
- Change (agent map): `get_agent_access` and `get_agent_inventory` answer for an agent with
  more than 512 policy pairs (policy coverage `unknown / limit_exceeded`); an `Expect`
  header other than `100-continue` gets 417; every MCP tool and parameter has its own
  description; `@shieldaai/agent-map/service` exports the service without the store or
  servers. The service and store are split into one module per operation and read phase.
- Change (viewer): the security sections lead each agent; every status, reason and field
  shows in plain words; long identifiers are shortened with a copy button; filters
  collapse and the sidebar stays in view; a "What am I looking at?" panel explains the
  map; a company session keeps its place when the tab is hidden and warns a minute before
  expiry; the demo runs the real service in the page. The viewer source is formatted and
  split into views and components.
- Upgrade note (agent map): projections imported before this change have no
  `delegated` or `derived` on tasks. Until the source publishes again, their boundary flags
  never read `absent` (the status is at most `unknown`) and identity scope reports
  `grant_lineage_unknown` for every granted tool. The new `untrusted_context_default`
  appears once as a changed tool field.
- Add (agent map): two discovery leads for all-teams readers, to help find agents the
  manifest does not declare. `list_undeclared_activity` lists tasks and caller principals
  that ran through an enrolled executor and belong to no declared agent, and
  `get_inventory_health` adds their count per source as `undeclaredActivity`.
  `list_unclaimed_identities` lists IAM roles and users of the enrolled AWS accounts that
  no declared agent's execution binding names, as candidates; a missing, stale or
  inconsistent collection reads `unknown`. A team-scoped reader gets a note without names
  or counts. A failed count never fails health. The viewer has a Discovery tab. No
  infrastructure, code or network scanning is added.
- Add (agent map): the "dangerous three" boundary flag. `get_agent_access` returns
  `boundaryFlags` with whether a live task can read private data, read outside content
  and send out, each leg `present`, `absent` or `unknown` with evidence, and a status of
  `exposed`, `mitigated`, `unknown` or `absent`. Only explicit `false` labels rule a tool
  out; a sensitive task or empty recipients stop only declared external sends.
  `list_agents` adds the status for the returned page with `includeFlags` (one extra
  read of those agents), and filters with `flag`/`flagStatus`. `get_agent_access` now also
  loads the in-scope delegation ancestors of the agent's tasks (after its own nodes, only
  if they fit) and asks which in-scope bindings of `*`-granted tools are sensitive, so list
  and detail agree.
- Add (agent map): outside-guard reach for resources. `list_resources` rows get
  `outsideGuard` (`yes`, `none_found`, `unknown` with reasons); `get_resource_access`
  lists the tool identities and declared direct paths that reach the resource. A manifest
  v3 `targetRef` must now name a declared host resource. A team reader's identity scope
  names only buckets mapped by in-scope bindings; anything else is a note without a
  count. `get_changes` reports
  declared direct paths under the new `outside_guard` change kind, labelled declared.
- Add (agent map): `get_agent_access.outsideGuard.identityScope` compares what each
  static tool identity can reach with what that tool's grants bind. For a read
  focused on one agent, the store reads every bucket in the account the identity has
  an IAM identity-policy candidate on and lists the unbound ones (`broader_than_grants`),
  or reports `matches_grants`; anything missing, stale, malformed or over 500 buckets is
  `unknown` with a reason. Each tool lists at most 100 extra buckets; a cut list is marked
  `truncated` and keeps its status. Only identity policies are evaluated, so results are
  candidates. The candidate layer already covers every bucket; the collector adds only the
  task `delegated` and `derived` facts used to check task liveness.
- Implement the Agent Map/Cartography catalog for agents, owners, permissions,
  host-bound resources, opaque credential references, relationships and retained
  before/after changes, with scoped pagination and accessible browser workflows.
- Fix (viewer): when a company page returns from the background under a different session
  (a new sign-in, possibly by someone else), everything read under the previous session is
  cleared and the map opens afresh with a notice. Before, the open agent and the owner and
  environment suggestions of the previous session stayed on screen. A company workspace is
  covered from the moment the page is hidden until the session check on return has passed;
  it keeps its layout, scroll position and keyboard focus.
- Fix (viewer): Discovery marks an AWS account whose collection is stale and no longer
  gives the all-clear for it; an agent whose policy evidence was not loaded shows "not
  evaluated", never "0" or an empty list; the owner and environment filters accept any typed
  value again; connecting no longer shows an empty inventory for one frame; Discovery and
  Changes pick the first source when health arrives late; a graph property named like a
  built-in (`constructor`, `__proto__`) no longer breaks the evidence panel.
- Fix (agent map): `get_agent_inventory` reports `counts.policies` and the `policies`
  section `total` as `null`, not `0`, when policy evidence was not evaluated; `100 Continue`
  is no longer sent to HTTP/1.0 clients. Owners in `get_agent_inventory` no longer carry
  `agentCount` and `resourceCount`; invalid store options throw `MAP_CONFIG_INVALID`; an
  unmet `Expect` header is 417. Neo4j 5.23 or later is required.
- Fix (agent map): listings no longer read policy evidence and lookups read only their own
  pairs, so the 512-pair policy limit no longer fails them; health and
  `find_agents_with_access` report policy coverage `unknown / limit_exceeded` past it. Store
  limits are configurable (`maxNodes` up to 10,000; defaults unchanged). Full-graph reads
  are estimated to work up to roughly 150 agents by default and roughly 800 at the maximum;
  limits above the defaults have not been run against a Neo4j database.
- Fix (agent map): `get_agent_access` returns its evidence with `graphStatus: too_large`
  when the graph exceeds the display cap; `find_agents_with_access` reaches its documented
  limit and returns `truncated: true` when its work budget runs out.
- Fix (agent map): the identity endpoint ignores other applications' cookies; ID token
  `iat`/`nbf` may be up to 5 seconds ahead (`oidc.clockToleranceSeconds`); `Expect:
100-continue` is answered; names sort in code-point order; `get_changes` accepts
  `changeKind: inventory` and shows renamed agents under their current name; evidence rows
  carry allowlisted properties only; launchers print `MAP_START_FAILED <code>: <hint>` and
  accept `--version`.
- Fix (viewer): the workspace opens on the agent listing alone and shows health separately
  with a retry; a failed selection is no longer highlighted; duplicate requests on connect
  and on the Permissions tab are gone; owner and resource searches wait 300 ms.
- Fix (agent map): `list_resources` judges outside-guard reach for the returned page only.
- Fix (agent map): the store's relationship query no longer scans every node in the
  database; it starts from the snapshot. Neo4j plan tests now check the boundary reads
  (one-agent, page-of-agents and full flags, outside-guard, summary and history, for team
  and all-teams readers) for cartesian products and all-node scans.

### Agent Ops and deployment

- Change (Agent Ops review screen): the review opens with a plain sentence of the effect,
  shows who asked (person or agent) and when, and counts down to expiry. Approval is two
  steps with Deny first; a denial can carry a reason; a requester can withdraw a pending
  request. New requests appear without a manual refresh, the session survives a tab
  switch, and Approve is not offered on your own request when self-approval is forbidden.
  The client is split into ES modules that share one contract with the service.
- Add (Agent Ops): opt-in online retention. With `requests.autoArchiveAfterDays`, the
  service archives the executor task families of finished requests older than that,
  10 per minute, through the operator's retire-then-archive path; blocked requests are
  skipped. History compaction stays offline.
- Add company onboarding, TLS/OIDC preflight, add-only reviewed ticket imports,
  an operator Setup view and paging for larger company datasets.

- Add the single-owner Linux Agent Ops service with durable ticket updates,
  authenticated OIDC approvals, scoped agent proposals and receipt-only recovery.
- Add hardened Docker Compose deployment, recovery runbooks, real-service browser
  checks and a Linux production-profile CI job.
- Add reviewed company-history compaction with permanent retirement fences,
  independent encrypted history mirrors and exact receipt lookup.
- Add authenticated operational status, bounded metrics, minimized activity
  exports and explicit distinction between readable storage and enrolled recovery.
- Make self-hosted ticket/request capacity, live-store byte limits and retained
  key limits safely configurable through reviewed offline policy changes.
- Enforce startup TLS/custody checks, remove unused runtime package managers,
  and add dependency inventory, production-image comparison and three-browser CI.
- Stop history growth before it exceeds the backup/recovery closure limit,
  reserve capacity for interrupted compaction and expose operator capacity alerts.
- Fix (Agent Ops): an unconfirmed request with no receipt can be closed as not applied even
  after another request changed its ticket; the close-out evidence shows the ticket as
  reviewed beside the ticket as it is now, and a preview taken before the ticket changed is
  refused with `CLOSE_OUT_STALE`. An approval whose outcome the executor has not recorded,
  no longer holds, or reports in an unrecognised form stays unconfirmed and is never marked
  failed; a request is never marked failed while a receipt for it exists. Reconcile and
  close-out accept an executor action left running or admitted.
- Fix (Agent Ops): one client address holds at most 4 of the 16 request slots for clients
  that are not signed in; when the sign-in table is full a new sign-in replaces the oldest
  pending one (`LOGIN_CAPACITY_REACHED` is no longer returned); the page and its files no
  longer count against the per-address request limit; `POST /auth/login` from a signed-in
  session answers `409 ALREADY_SIGNED_IN`; approve and deny answer `409 REVIEW_STALE` when
  the request no longer matches the reviewed fingerprint or its stored action is gone.
  `deployment/production/verify-cli.mjs` uses the cookie renewed by `POST /auth/login`.
- Fix (Agent Ops service): TLS handshake and idle timeouts, a per-address connection cap,
  in-flight slots reserved for signed-in sessions, cached readiness, one state decode per
  revision, aggregated anonymous refusal events, reserved `system:` actor ids and one
  archive rule. The production image ships only the modules the service imports.
- Fix (Agent Ops): a backend refusal that provably happened before any effect
  (authorization revoked, ticket changed, storage or clock refusal) ends the request as
  failed or "target changed" with a recorded cause instead of "Outcome unconfirmed". An
  operator can close a stuck unconfirmed request as not applied after reviewing evidence
  that no receipt exists (`POST /api/requests/:id/close-out`).
- Fix (Agent Ops): at the per-address sign-in cap the oldest pending sign-in is replaced
  instead of answering 429; `sessionTtlMs`, `rateLimitPerMinute` and `signInFlowsPerClient`
  are bounded configuration keys. A sign-in page left open past five minutes renews its
  cookie and retries. Non-browser clients must use the cookie set by `POST /auth/login`.
- Fix (Agent Ops): `compact-history --apply` compacts exactly the reviewed batch; history
  files with a wrong mode, owner or link count report `HISTORY_EVIDENCE_INVALID`; history
  segments decrypt only with a 12-byte nonce and a full 16-byte tag; agent proposals outside
  the ticket allowlist get the same 403 whether or not the ticket exists; an unparseable
  request target answers 400, not 503.
- Fix (Agent Ops): 5xx answers log one `REQUEST_FAILED` event with a safe cause; requests
  and the activity log keep a cause code; `START_FAILED` names the failing step and
  configuration key. The UI reloads after a definitive refusal instead of blanking, and
  "Review required" reads "Needs a new request". TLS alerts say to reload with SIGHUP.
- Fix (Agent Ops): refusing a self-approval answers 409 instead of 403, which signed the
  reviewer out.
- Fix (Agent Ops): anonymous `GET /api/session` no longer creates server-side
  sessions, so cookieless traffic can't exhaust the session table and block sign-in.
  Pre-login state is a signed five-minute cookie with a derived CSRF token, and each
  client address may hold at most four pending sign-ins. The rate limiter keys IPv6
  by /64 and drops the oldest window when full instead of refusing new clients.
  New `requests` settings add per-requester (50) and per-tenant (1,000) pending
  caps, configurable review expiry (default unchanged at 5 minutes) and opt-in
  `forbidSelfApproval`. `SIGHUP` now also reloads TLS material without a restart.

### Collector

- Change (collector): `agent-guard-recovery` and `agent-guard-map-report` are installed
  commands; the collector, lifecycle and recovery commands take the same archive, lock and
  Neo4j options; the lifecycle
  command no longer creates a mistyped archive directory (`--create`); `neo4j` and
  `referencing` are declared dependencies; the unused permission-mapping file is no longer
  bundled. Archive bookkeeping uses an in-memory index, each snapshot is schema-validated
  once per process, and imports no longer issue cleanup statements that could not match.
- Change (collector): every command reports failures as `{"status":"failed","code":…}`
  with specific Neo4j and path codes and a `--verbose` flag (lifecycle and recovery errors
  were `{"error":…}`); `pilot_benchmark` is no longer in the wheel.
- Patch the Python Cartography OAuthLib dependency and add locked cross-platform
  advisory checks; retain explicit, secret-free benchmark failure diagnostics.
- Fix (collector): every command that names an archive locks `<archive directory>.lock`
  beside it, so commands on one archive exclude each other from any working directory;
  `--lock-file` is held in addition and no longer has a default (a file import without it
  still locks `.agent-guard-cartography.lock` in the working directory).
- Fix (collector): a newly collected snapshot that the graph refuses as older than its
  published view (`GENERATED_AT_ROLLBACK`, `REVISION_ROLLBACK`) is reported and no longer
  kept as a pending receipt, so an executor clock step-back cannot exhaust a source's
  pending allowance. Archive retention removes only published receipts; `discard --reviewed`
  can remove a receipt whose outcome was never confirmed, and refuses one whose file is
  unsafe or unreadable instead of deleting it as damaged. The running collector notices
  mode, owner and link changes to archive files and never prunes a file that changed since
  it was indexed. `agent-guard-map-report` reports failures as JSON with the specific code.
  A snapshot whose `ledgerRevision` or `policyEpoch` is not a true integer is rejected.
- Fix (collector): the archive prunes the oldest published snapshots early
  (`ARCHIVE_RETENTION_SHORTENED`) instead of failing every source when full;
  `--archive-retention-seconds` is new; `--watch` warns or refuses at startup when sources,
  interval and retention cannot fit. With defaults the archive holds two sources.
- Fix (collector): pending receipts are capped per source (`--archive-max-pending`), listed
  and discarded with `agent-guard-recovery pending` / `discard --reviewed`; a foreign or damaged
  file fails only its own source and is named; backup, restore and the new `agent-guard-recovery
replay` accept the archive limit flags.
- Fix (collector): at an unchanged ledger revision a capture older than the published one
  is refused (`GENERATED_AT_ROLLBACK`); SIGTERM stops `--watch` cleanly; the AWS worker's
  process group is signalled only while its leader is unreaped.

### Documentation, tests and repository

- Docs: the README shows how to connect the guard to a model (one dispatcher function) and
  maps the repository's folders; the release notes open with what 1.0 contains; the
  executor README has a "Keeping state across a restart" section; `CONTRIBUTING.md` starts
  with setup and how to run one test. New runnable examples `examples/agent-loop.mjs` and
  `examples/restart.mjs`, and an [examples guide](examples/README.md). The documents no
  longer say approvals survive a restart: budgets, revocations and used approvals do, and
  an action that had not run is reviewed again. The `POLICY_CHANGED` catalog text says so.
- Release preflight requires every `release-state.json` evidence entry to be a
  committed repository file.

- Docs: the README is rewritten around the problem, how the guard works, what it stops and
  what it does not; new [glossary](docs/glossary.md), [docs index](docs/README.md) and
  [standards and further reading](docs/standards.md); the risk table gains a "does not
  cover" column. The dated evidence files, archived plans and reviews, and the notes for
  unpublished versions are removed from the repository.
- Docs: package READMEs, the API contract, threat model, architecture, scenarios, support
  and limits, the package guide and every guide are rewritten for first-time readers; new
  guides for [delegation](docs/guides/delegation.md) and the
  [audit log](docs/guides/audit-log.md); the inventory formats have a reference page.
- Docs: [risks mapped to the OWASP Top 10 for Agentic Applications](docs/risks.md), with
  the package that handles each, and a plain statement of
  [how agents get onto the map](docs/guides/agent-cartography.md#how-agents-get-onto-the-map):
  only by being declared in a host manifest (the discovery leads above only point at
  candidates).
- Docs: one [Support and limits](docs/support-and-limits.md) page replaces the
  protection design, assessment, acceptance and production-readiness documents;
  earlier plans and reviews are removed from the repository; `releasing.md` is cut to a
  checklist, commands and rollback; the README gains a tested five-minute example
  and a maturity table (stable / experimental / reference app); the threat model
  covers Agent Ops; the API contract drops "Alpha". New releases link CI runs
  instead of committing dated evidence JSON. A test checks every relative Markdown
  link in the repository.
- Test: seeded property tests for `canonicalJson`/`digestJson` (stable under key
  order, round-trip, injective across 3,000 generated values, no cross-type digest
  collisions) and model-based tests of budgets and reservations under random
  interleavings, in core (60 seeds) and the durable executor (25 seeds, with
  reconciliation and restart). Both model tests fail when reservation release is
  broken. They use a small seeded generator instead of a new dependency.

## 0.1.0-alpha.3 — 2026-11-05

- Harden policy admission, approval expiry, cancellation, task authentication,
  response validation and bounded callback capacity.
- Bind approved sandbox inputs to the bytes actually staged; reject unsafe
  workspace paths and add an opt-in independent rollback witness.
- Add scoped MCP credential management, signed build and pilot evidence,
  provider outcome evaluation and operator-study tooling.
- Clarify Agent Map authorization, stale-result handling, recovery and mobile
  navigation; fix installed command launchers.
- Publish protection requirements, design, engineering review and reproducible
  validation evidence. SDK publication remains experimental and does not certify
  a production deployment.

## 0.1.0-alpha.2 — 2026-11-04

Published all five npm packages under the `alpha` tag. The release notes cover
registry verification and the workaround for the two Agent Map command shortcuts
on macOS.

- Correct Windows test paths and close the pilot's SQLite owner before deleting
  its fixture directory. Resolve native filesystem aliases in release root
  validation while retaining nested-directory and dirty-checkout rejection.
- Fix the local pilot launcher's configuration-file race by opening one
  nonblocking, no-follow descriptor before validating private metadata. Cover
  FIFO replacement and keep Node 22 runtime warnings separate from exact test
  assertions about safe application diagnostics.
- Reject staged graph projections where duplicate memberships or endpoint edges
  conceal missing relationships. Validate distinct nodes and expected endpoint
  pairs as well as totals before changing the published snapshot.
- Open private difference-report files nonblocking and revalidate descriptor
  ownership, permissions, link count and size. Reject FIFO replacements and
  same-inode safety changes without leaving an open descriptor.
- Reduce cold Neo4j planning cost for scoped policy checks by expressing the
  binding proof as correlated short paths. Preserve exact scope/identity checks,
  all duplicate-edge guards and the five-second read deadline; cover every guard
  with a committed-change regression and make refresh-clock tests deterministic.
- Bound bearer reference-launcher configuration reads on the opened regular-file
  descriptor. Reject named pipes before reading and cap files that grow after
  metadata inspection; preserve regular-file symlinks and safe startup errors.
- Clear company viewer evidence and abort sibling reads immediately on any
  HTTP 401/403, regardless of denial-body framing, size or completion. Keep
  ordinary error handling and bounded response parsing unchanged.
- Reject nonregular Cartography input files before reading so named pipes cannot
  stall import/enrollment startup. Preserve regular-file symlinks and input limits;
  align lifecycle identifiers with the shared whitespace/BOM validation rule.
- Preserve original task/tool and visible MCP observation times in Agent Map
  freshness, including historical snapshots; recomposition cannot renew old
  evidence. Keep missing timestamps unknown and reject malformed core coverage.
- Preserve resource case through Cartography's S3 bucket-summary matcher while
  retaining case-insensitive actions. Correct both invented Allow candidates and
  candidates suppressed by mismatched Deny resources; refresh existing captures
  and Guard joins to replace previously published evidence.
- Reject BOM-only or mixed-whitespace enrollment identifiers consistently across
  observer, cloud-join and AWS collection configuration; preserve nonblank values.
- Reject non-ASCII digits in Cartography cloud account enrollment, including
  revalidated `CloudScope` objects, to match the AWS collector and inventory
  schemas. Add six regression cases and installed-wheel checks; document the
  existing graph-replay size limits.
- Bound each disposable Neo4j readiness handshake to two seconds using the
  driver's acquisition deadline. Verify silent-peer timeout and successful
  retry/query behavior without relaxing the overall startup deadline.
- Enforce archive file-count capacity before new writes and reserve snapshot/
  receipt capacity together. Align standalone and embedded inventory schemas
  with TypeScript validation for token boundaries and blank Unicode identifiers.
- Fix Cartography receipt replay bypassing archive lifecycle/recovery fences;
  incomplete reconstruction now also blocks collector work and archive pruning
  before evidence changes. Added CLI replay and concurrent source-retirement
  regression coverage.

- Add explicit source-generation supersession with a private transition journal,
  graph publication fences, active-source reads and bounded retirement after a
  grace period. Preserve replacement decisions through backup/replay and reject
  incomplete lifecycle or recovery state.
- Reject complete policy evidence from custom map stores when owning-agent or
  grant/tool/selector links are missing or ambiguous. Preserve valid multiple
  grants and explicit unavailable evidence. Add real-Neo4j regressions for team,
  deployment and identity changes between policy reads.
- Expose scoped IAM policy candidates through the existing reference HTTP/MCP
  API and viewer. Verify exact task/deployment/binding paths, collection ownership,
  provider consistency and independent freshness; bound and recheck reads.
  Preserve original object/prefix scope, unresolved coverage and unknown
  assessments. Add condition/timestamp cards and dashed graph edges, while
  excluding live policy evidence from historical snapshot comparisons.
- Add explicit opt-in IAM identity-policy evidence to AWS collection. Resolve
  complete user/group/role/managed-policy references, bound policy bytes and mapper
  work, and suppress candidates for unresolved boundaries or unsupported policies.
  Atomically replace owned S3 candidate edges with minimized condition metadata,
  preserving shared Cartography relationships. Keep assessments unknown and raw
  policy documents inside the capture worker.
- Add explicit single-account AWS metadata collection with exact caller checking,
  frozen temporary credentials, bounded verified HTTPS exchanges and an owned
  deadline-limited worker. Atomically publish pinned Cartography role/user/bucket
  schemas and collection membership; preserve shared provider nodes while making
  removed or changed evidence unresolved. Coordinate hourly AWS refresh inside
  the existing observer lock owner, isolate failures and emit safe receipts.
  Add offline SDK/transport, orchestration and real-Neo4j tests. Live enrollment
  remains deployment work.
- Add a dedicated company OIDC/HTTPS Agent Map endpoint and private launcher.
  Verified signed identities select explicit host-owned scopes; bounded code/PKCE
  exchanges, server-side sessions, CSRF, logout and revocation protect browser
  reads. The viewer discovers authentication mode and clears rejected/expired
  sessions. Add disposable HTTPS provider, packaged-client and real-Neo4j scope
  checks. Company provider enrollment and trusted-browser rollout remain separate.
- Add an isolated Cartography pilot with authenticated loopback Compose, real
  exporter/observer/collector/reference wiring, private versioned archive backups,
  fresh-graph replay and executor rollback checks. Add minimized 30-day difference
  reports, gated graph-load and admission-under-polling benchmarks, safe CI evidence artifacts
  and an operational runbook. Bound repeated opaque-reference hashing to each
  snapshot; the corrected admission benchmark passes its 10% target after this
  change, with earlier failed evidence retained. Company identity/cloud rollout
  remains an explicit deployment gate; the pilot creates no public service or
  scheduled cloud sync.
- Add the optional Agent Map reference service and React/Cytoscape viewer:
  host-defined company/tenant/team scope, bounded fixed Neo4j reads, equivalent
  HTTP/MCP evidence, focused graphs, conservative access explanations, exact
  potential-access lookup, snapshot differences and component freshness.
  Validate hidden/shared/moved ownership against disposable Neo4j; keep all
  inventory outside executor admission. Company SSO/TLS deployment remains pilot work.
- Add a bounded, enrolled observer collector with serialized polling, private
  snapshot/health receipts, restart replay and scoped retention. Join host AWS
  references to fresh, exact provider inventory with explicit unresolved evidence
  and preserved object/prefix scope; package the pinned S3 permission mapping.
- Add managed MCP inventory with lifecycle and descriptor drift revisions, opaque
  transport references, bounded host-mcp snapshot composition and observer delivery.
  Cartography projects connection/operation evidence with replay checks and explicit
  unavailable records; inventory never grants or approves execution.
- Add validated host-owned inventory manifests, immutable host-profile composition,
  explicit deployment/resource/execution bindings and independently versioned
  Cartography metadata projections. Host assertions never widen executor authority.
- Add a separate loopback inventory observer with namespaced credentials, fixed
  tenant scopes, bounded requests/responses, deadlines, quotas and concurrency
  limits; verify HTTP snapshots against the independent Cartography contract.
- Add the opt-in executor inventory exporter: persistent ledger identity with
  atomic legacy migration, immutable tenant snapshots, opaque resource references,
  strict bounds and independent TypeScript/Python contract checks for Cartography.
- Add the experimental `@shieldaai/agent-guard-executor` workspace: encrypted SQLite
  admission, task/admin authentication, conservative crash recovery, scoped model
  dispatch, versioned private files, restricted HTTP and governed memory.
- Add typed argument normalization and resource-version binding to the shared core;
  extend the conformance catalog to twelve paired scenarios (catalog 1.2.0).
- Add managed MCP connections with session-bound approval, bounded local schemas,
  metadata quarantine, explicit resources/prompts and restricted HTTP transport.
- Add a pinned-image Docker workload profile with bounded copy-in, isolated Linux
  execution and separately reviewed exports. Real macOS/Linux-VM tests pass; native
  Linux/Windows host runs and independent review remain protected-release gates.
- Add platform CI, clean packaged-consumer checks and adversarial recovery,
  transport, memory, adapter and isolation tests. Package publication does not
  certify the full native platform isolation or company deployment boundary.

## 0.1.0-alpha.1 — 2026-10-24

Published all three packages under `@shieldaai` with the `alpha` dist-tag. The [GitHub prerelease](https://github.com/ShieldaAI/agent-guard/releases/tag/v0.1.0-alpha.1) includes the verified tarballs and checksums.

- Check deadlines again when a handler result settles, so synchronous work cannot return success
  after its deadline while the cancellation timer is waiting to run.
- Enforce the canonical JSON byte limit during normalization instead of building an oversized
  serialization before rejecting it.
- Disable persisted CI checkout credentials, bound workflow runtimes, and add CodeQL, dependency review and Dependabot configuration.
- Clarify package selection and the local demo setup; no provider credentials are needed.
- Reject custom policy decisions when their supplied task snapshot changes during evaluation, before a handler runs or an approval is consumed.
- Strengthen scenario catalog 1.1.0 to detect premature dispatch and incorrect cost settlement; bound asynchronous conformance cases with configurable timeouts.
- Exercise the MCP bridge against the official SDK v2.4.0 and document the difference between local request cancellation and remote work stopping.
- Remove obsolete build output and rebuild packages before packing.
- Compile packed public types and README examples, execute a packaged MCP consumer, and require a clean committed checkout with aligned versions before publication.

These changes are not included in the earlier `0.1.0-alpha.0` packages.

## 0.1.0-alpha.0 — 2026-10-24

Published all three packages under `@shieldaai` with the `alpha` dist-tag.

- Initial TypeScript execution core for explicitly registered tools and scoped task trees.
- Immutable prepared actions, exact approvals, tenant and recipient gates, shared sensitivity, literal secret scanning and atomic local budgets.
- MCP client bridge with explicit approval of tool metadata.
- Ten versioned protective scenarios with malicious and benign executable fixtures.
- Package-consumer verification, CI, threat model and release documentation.

This alpha is experimental and keeps state in one process. See the threat model for deployment requirements and limitations.
