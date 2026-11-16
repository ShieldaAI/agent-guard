import { ASI, LOCAL_HOST, PIPE_TO_SHELL, REMOTE_FETCH, agentServers, hooks, rule, serverLabel } from './common.js';
import type { Rule } from './common.js';
import { dockerImage, runnerPackage, splitSpec } from '../mcp.js';
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
        const runner = runnerPackage(server.command, server.args);
        if (runner) {
          const { name, version } = splitSpec(runner.spec);
          // A project dependency or a local path resolves inside the repo, not from the registry.
          if (
            runner.localOnly ||
            project.dependencies.has(name) ||
            /^(\.{1,2}\/|\/|file:|link:|workspace:)/.test(runner.spec)
          )
            continue;
          if (
            !version ||
            version === 'latest' ||
            version === 'next' ||
            version.startsWith('^') ||
            version.startsWith('~')
          )
            report({
              message: `${serverLabel(server)} starts "${runner.spec}" with ${runner.runner} and no pinned version, so every new release runs automatically.`,
              location: server.location,
              subject: `server:${server.name}`,
              fix: `Pin an exact version, for example "${name}${runner.runner === 'uvx' || runner.runner === 'pipx' ? '==' : '@'}<version>".`,
            });
          continue;
        }
        const image = dockerImage(server.command, server.args);
        if (image && !image.includes('@sha256:') && (!/:[^/:]+$/.test(image) || image.endsWith(':latest')))
          report({
            message: `${serverLabel(server)} runs image "${image}" with no fixed tag or digest.`,
            location: server.location,
            subject: `server:${server.name}`,
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
          subject: `server:${server.name}`,
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
];
