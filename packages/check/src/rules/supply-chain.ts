import {
  ASI,
  LOCAL_HOST,
  serverKey,
  PIPE_TO_SHELL,
  REMOTE_FETCH,
  agentServers,
  hooks,
  rule,
  serverLabel,
} from './common.js';
import type { Rule } from './common.js';
import { dockerImage, isPinnedSpec, runnerSpecs, splitSpec } from '../mcp.js';
import { lineAt } from '../text.js';

export const SUPPLY_CHAIN_RULES: readonly Rule[] = [
  rule(
    {
      id: 'AGC-SUP-001',
      title: 'MCP server runs an unpinned package',
      severity: 'high',
      confidence: 'high',
      owasp: [ASI.supply],
      help: 'npx, uvx and docker fetch whatever is newest at start-up. A compromised release then runs with the agent’s access.',
    },
    (project, report) => {
      for (const server of agentServers(project)) {
        const { specs, unverifiable } = runnerSpecs(server.command, server.args);
        if (unverifiable) {
          report({
            message: `${serverLabel(server)} starts a shell line with more than one command, so what it fetches and runs cannot be checked.`,
            location: server.location,
            subject: `server:${serverKey(server)}:shell`,
            fix: 'Start the server with one command, with its package pinned to an exact version.',
          });
          continue;
        }
        for (const runner of specs) {
          const { name } = splitSpec(runner.spec);
          // A project dependency or a local path resolves inside the repo, not from the registry.
          if (
            runner.localOnly ||
            project.dependencies.has(name) ||
            /^(\.{1,2}\/|\/|file:|link:|workspace:)/.test(runner.spec)
          )
            continue;
          if (!isPinnedSpec(runner.runner, runner.spec))
            report({
              message: `${serverLabel(server)} starts "${runner.spec}" with ${runner.runner} and no pinned version, so every new release runs automatically.`,
              location: server.location,
              subject:
                specs.length > 1 && runner !== specs[0] ? `server:${server.name}:${name}` : `server:${server.name}`,
              fix: `Pin an exact version, for example "${name}${runner.runner === 'uvx' || runner.runner === 'pipx' ? '==' : '@'}<version>".`,
            });
        }
        if (specs.length) continue;
        const image = dockerImage(server.command, server.args);
        if (image && !image.includes('@sha256:') && (!/:[^/:]+$/.test(image) || image.endsWith(':latest')))
          report({
            message: `${serverLabel(server)} runs image "${image}" with no fixed tag or digest.`,
            location: server.location,
            subject: `server:${serverKey(server)}`,
            fix: 'Pin the image by digest: image@sha256:<digest>.',
          });
      }
    },
  ),
  rule(
    {
      id: 'AGC-SUP-002',
      title: 'Remote MCP server over plain HTTP',
      severity: 'high',
      confidence: 'high',
      owasp: [ASI.supply],
      help: 'Without TLS, anyone on the network path can read the traffic and replace tool descriptions or results.',
    },
    (project, report) => {
      for (const server of agentServers(project)) {
        if (!server.url?.startsWith('http://')) continue;
        let host = '';
        try {
          host = new URL(server.url).hostname;
        } catch {
          continue;
        }
        if (LOCAL_HOST.test(host)) continue;
        report({
          message: `${serverLabel(server)} connects to ${host} over plain HTTP.`,
          location: server.location,
          subject: `server:${serverKey(server)}`,
          fix: 'Use https://.',
        });
      }
    },
  ),
  rule(
    {
      id: 'AGC-SUP-003',
      title: 'Remote content loaded into the agent at runtime',
      severity: 'high',
      confidence: 'high',
      owasp: [ASI.supply, ASI.goal],
      help: 'Hook output from SessionStart and UserPromptSubmit becomes part of the agent’s context. Fetching it from a URL lets whoever controls that URL instruct the agent.',
    },
    (project, report) => {
      for (const hook of hooks(project))
        if (
          (hook.event === 'SessionStart' || hook.event === 'UserPromptSubmit') &&
          REMOTE_FETCH.test(hook.command) &&
          !PIPE_TO_SHELL.test(hook.command)
        )
          report({
            message: `A ${hook.event} hook fetches a URL; its output goes straight into the agent's context.`,
            location: hook.location,
            subject: `hook:${hook.event}:${hook.command}`,
            fix: 'Keep the instructions in the repo, or pin the content by checksum before using it.',
          });
    },
  ),
  rule(
    {
      id: 'AGC-SUP-004',
      title: 'Download piped into a shell',
      severity: 'critical',
      confidence: 'high',
      owasp: [ASI.supply, ASI.code],
      help: 'curl … | sh runs whatever the server returns at that moment, with the agent’s access.',
    },
    (project, report) => {
      for (const hook of hooks(project))
        if (PIPE_TO_SHELL.test(hook.command))
          report({
            message: `A ${hook.event} hook pipes a download into a shell.`,
            location: hook.location,
            subject: `hook:${hook.event}:${hook.command}`,
            fix: 'Vendor the script into the repo, or download it, verify a checksum, then run it.',
          });
      for (const file of project.scripts) {
        const match = PIPE_TO_SHELL.exec(file.text);
        if (match)
          report({
            message: 'A skill or hook script pipes a download into a shell.',
            location: { file: file.path, line: lineAt(file.text, match.index) },
            subject: 'script',
            fix: 'Vendor the script, or verify a checksum before running it.',
          });
      }
      for (const file of project.prompts) {
        const match = PIPE_TO_SHELL.exec(file.text);
        if (!match) continue;
        // Text that warns against the command ("never run …", "do not …"), in its paragraph or under a
        // heading that says so, is not an instruction to run it.
        const paragraph = file.text.slice(Math.max(0, file.text.lastIndexOf('\n\n', match.index)), match.index);
        const headingAt = file.text.lastIndexOf('\n#', match.index);
        const heading = file.text.slice(headingAt + 1, file.text.indexOf('\n', headingAt + 1));
        const negation = /\b(never|do not|don't|avoid|must not|dangerous)\b/i;
        if (
          negation.test(paragraph) ||
          (headingAt >= 0 && negation.test(heading)) ||
          (headingAt < 0 && file.text.startsWith('#') && negation.test(file.text.slice(0, file.text.indexOf('\n'))))
        )
          continue;
        report({
          message: 'Agent instructions tell it to pipe a download into a shell.',
          location: { file: file.path, line: lineAt(file.text, match.index) },
          subject: 'prompt',
          severity: 'medium',
          confidence: 'low',
          fix: 'Install the tool ahead of time, or give the agent a pinned, checksummed install step.',
        });
      }
    },
  ),
  rule(
    {
      id: 'AGC-SUP-005',
      title: 'Plugin or marketplace not pinned',
      severity: 'medium',
      confidence: 'high',
      owasp: [ASI.supply],
      help: 'Claude Code plugins can add hooks, MCP servers, commands and skills, which run with the agent’s permissions. A source with no commit pin installs whatever the branch holds when it is fetched; autoUpdate fetches again in the background.',
    },
    (project, report) => {
      for (const source of project.pluginSources) {
        const full =
          source.type === 'archive'
            ? /^[0-9a-fA-F]{64}$/.test(source.sha ?? '')
            : /^[0-9a-f]{40}$/.test(source.sha ?? '');
        if (source.kind === 'plugin') {
          if (source.type === 'npm') {
            if (source.version && /^\d+\.\d+\.\d+(-[\w.]+)?$/.test(source.version)) continue;
            report({
              message: `Plugin "${source.name}" installs npm package ${source.from}${source.version ? ` at range ${source.version}` : ' at its latest version'}.`,
              location: source.location,
              subject: `plugin:${source.name}`,
              fix: 'Set version to an exact release, such as "1.4.2".',
            });
          } else if (source.type === 'archive' && !full)
            report({
              message: `Plugin "${source.name}" downloads an archive from ${source.from} with no sha256, so whatever the server returns is installed.`,
              location: source.location,
              subject: `plugin:${source.name}`,
              fix: 'Add "sha256" with the digest of the archive you reviewed.',
            });
          else if (!full)
            report({
              message: `Plugin "${source.name}" comes from ${source.from}${source.ref ? ` at ${source.ref}` : ''} with no sha, so a push to that ${source.ref ? 'ref' : 'repository'} changes what runs.`,
              location: source.location,
              subject: `plugin:${source.name}`,
              severity: source.ref ? 'low' : 'medium',
              fix: 'Add "sha" with the full 40-character commit you reviewed.',
            });
          continue;
        }
        // Marketplace sources accept a ref but not a sha.
        if (source.ref && !source.autoUpdate) continue;
        if (source.type === 'url' && !source.autoUpdate) continue; // one file: takes no ref
        report({
          message: `Marketplace "${source.name}" comes from ${source.from}${source.ref ? ` at ${source.ref}` : ' at its default branch'}${source.autoUpdate ? ' and updates itself in the background' : ''}.`,
          location: source.location,
          subject: `marketplace:${source.name}`,
          severity: source.autoUpdate && !source.ref ? 'high' : source.autoUpdate ? 'medium' : 'low',
          fix: 'Set "ref" to a release tag and autoUpdate to false; pin each plugin in the marketplace with a sha.',
        });
      }
    },
  ),
];
