import { ASI, rule } from './common.js';
import type { Rule } from './common.js';
import type { Severity } from '../types.js';
import { bashScope } from '../claude.js';
import { UNTRUSTED_TRIGGERS } from '../workflows.js';

export const WORKFLOWS_RULES: readonly Rule[] = [
  rule(
    {
      id: 'AGC-TRG-001',
      title: 'Agent triggered by outsiders with write access',
      severity: 'high',
      confidence: 'high',
      owasp: [ASI.goal, ASI.identity],
      help: 'Issue, comment and pull-request text is written by anyone. An agent that reads it while holding a write token can be told to use that token.',
    },
    (project, report) => {
      for (const step of project.workflows) {
        const untrusted = step.triggers.filter(trigger => UNTRUSTED_TRIGGERS.has(trigger));
        if (!untrusted.length) continue;
        // id-token: write only mints OIDC tokens; it is repository write access only through the app token.
        const repoWrite = step.permissions.write.filter(scope => scope !== 'id-token');
        const write = repoWrite.length > 0 || step.appToken || step.customToken !== undefined;
        if (step.permissions.known && !write) continue;
        const agent = project.agents.find(item => item.id === `workflow:${step.path}#${step.job}/${step.step}`);
        const open = step.nonWriteUsers?.value.trim() === '*';
        // claude-code-action only answers people with write access unless allowed_non_write_users widens it.
        // claude-code-action checks that whoever starts it can write to the repository; its base
        // action does not.
        const gated =
          step.action === 'claude-code-action' && !step.nonWriteUsers && !/base-action/i.test(step.uses ?? '');
        const broad =
          step.skipPermissions !== undefined ||
          step.allowedTools.some(
            r => r.tool === '*' || (r.tool === 'Bash' && ['any', 'network'].includes(bashScope(r.specifier))),
          );
        const severity: Severity =
          step.checksOutPullRequest || (open && broad) ? 'critical' : open || !gated || broad ? 'high' : 'medium';
        const scope = step.appToken
          ? 'Claude GitHub App token'
          : [...repoWrite, ...(step.customToken ? [`token secrets.${step.customToken.name}`] : [])].join(', ');
        const why = step.checksOutPullRequest
          ? 'and checks out the pull request’s own code under pull_request_target'
          : open
            ? `with write access (${scope || 'default token'}), and allowed_non_write_users is "*", so anyone can start it`
            : !step.permissions.known && !step.appToken
              ? 'and sets no permissions, so it gets the repository’s default token'
              : gated
                ? `with write access (${scope}); only people with write access can start it, but the text it reads can come from anyone`
                : `with write access (${scope})`;
        report({
          message: `The ${step.job} job runs an agent on ${untrusted.join(', ')} ${why}.`,
          location: step.checksOutPullRequest ?? step.nonWriteUsers?.location ?? step.location,
          subject: `${step.job}/${step.step}`,
          ...(agent ? { agent } : {}),
          severity,
          fix: step.checksOutPullRequest
            ? 'Do not check out untrusted code under pull_request_target; use pull_request instead.'
            : 'Set the narrowest permissions the job needs, and keep the agent read-only on untrusted events.',
        });
      }
    },
  ),
  rule(
    {
      id: 'AGC-LIM-001',
      title: 'No turn limit on an automated agent',
      severity: 'low',
      confidence: 'high',
      owasp: [ASI.cascade],
      help: 'Without a turn limit a looping or steered agent keeps spending until the job times out.',
    },
    (project, report) => {
      for (const step of project.workflows) {
        if (step.maxTurns || !step.action.startsWith('claude')) continue;
        const untrusted = step.triggers.some(trigger => UNTRUSTED_TRIGGERS.has(trigger));
        report({
          message: `The ${step.job} job sets no turn limit for the agent${step.timeout ? '' : ' and no timeout'}.`,
          location: step.location,
          subject: `${step.job}/${step.step}`,
          severity: untrusted && !step.timeout ? 'medium' : 'low',
          fix: 'Add --max-turns to claude_args.',
        });
      }
    },
  ),
  rule(
    {
      id: 'AGC-LIM-002',
      title: 'No timeout on an automated agent',
      severity: 'low',
      confidence: 'high',
      owasp: [ASI.cascade],
      help: 'GitHub’s default job timeout is six hours.',
    },
    (project, report) => {
      for (const step of project.workflows)
        if (!step.timeout)
          report({
            message: `The ${step.job} job has no timeout-minutes, so a stuck agent can run for six hours.`,
            location: step.location,
            subject: `${step.job}/${step.step}`,
            fix: 'Set timeout-minutes on the job.',
          });
    },
  ),
  rule(
    {
      id: 'AGC-IDN-001',
      title: 'Agent runs on a personal access token',
      severity: 'high',
      confidence: 'high',
      owasp: [ASI.identity],
      help: 'A personal token carries everything its owner can do, across every repository they can reach.',
    },
    (project, report) => {
      for (const step of project.workflows)
        for (const secret of step.secrets)
          if (/(^|_)PAT(_|$)|PERSONAL_ACCESS_TOKEN|PERSONAL_TOKEN/i.test(secret.name))
            report({
              message: `The ${step.job} job gives the agent secret ${secret.name}, which looks like a personal access token.`,
              location: secret.location,
              subject: `${step.job}:${secret.name}`,
              fix: 'Use a GitHub App token or the job’s GITHUB_TOKEN with narrow permissions.',
            });
    },
  ),
  rule(
    {
      id: 'AGC-TRG-002',
      title: 'Unattended agent changes the repository with no reviewer',
      severity: 'medium',
      confidence: 'high',
      owasp: [ASI.trust, ASI.cascade],
      help: 'A scheduled or push-triggered agent with write access acts with no person in the loop. A GitHub environment with required reviewers, or proposing changes as a pull request from a read-only job, puts one back.',
    },
    (project, report) => {
      for (const step of project.workflows) {
        if (step.environment) continue;
        if (step.triggers.some(trigger => UNTRUSTED_TRIGGERS.has(trigger))) continue; // AGC-TRG-001
        const automatic = step.triggers.filter(trigger => AUTOMATIC_TRIGGERS.has(trigger));
        if (!automatic.length) continue;
        const writes = step.permissions.write.filter(scope => scope === '*' || scope === 'contents');
        if (!writes.length && !step.appToken) continue;
        const agent = project.agents.find(item => item.id === `workflow:${step.path}#${step.job}/${step.step}`);
        report({
          message: `The ${step.job} job runs the agent on ${automatic.join(', ')} with ${step.appToken ? 'the Claude GitHub App token' : 'contents: write'} and nobody reviews before it acts.`,
          location: step.location,
          subject: `${step.job}/${step.step}`,
          agent,
          fix: 'Add a GitHub environment with required reviewers to the job, or give it contents: read and have it open a pull request.',
        });
      }
    },
  ),
  rule(
    {
      id: 'AGC-IDN-002',
      title: 'Agent gets long-lived cloud keys',
      severity: 'medium',
      confidence: 'high',
      owasp: [ASI.identity],
      help: 'Static cloud keys work from anywhere until someone rotates them. Workload identity (OIDC) gives the job short-lived credentials scoped to the repository and branch.',
    },
    (project, report) => {
      for (const step of project.workflows)
        for (const secret of step.secrets)
          if (STATIC_CLOUD_KEY.test(secret.name))
            report({
              message: `The ${step.job} job hands secret ${secret.name}, a long-lived cloud key, to the agent step.`,
              location: secret.location,
              subject: `${step.job}:${secret.name}`,
              fix: 'Use OIDC: aws-actions/configure-aws-credentials with role-to-assume, google-github-actions/auth with workload_identity_provider, or azure/login with a federated credential.',
            });
      for (const server of project.servers)
        for (const key of Object.keys(server.env))
          if (STATIC_CLOUD_KEY.test(key))
            report({
              message: `MCP server "${server.name}" gets ${key}, a long-lived cloud key.`,
              location: server.location,
              subject: `server:${server.client}:${server.name}:${key}`,
              fix: 'Give the server a short-lived role or profile (for example AWS_PROFILE with SSO) instead of static keys.',
            });
    },
  ),
];

/** Events that start a run with nobody choosing to: a schedule, a push, another system. */
const AUTOMATIC_TRIGGERS = new Set([
  'schedule',
  'push',
  'repository_dispatch',
  'check_suite',
  'status',
  'deployment_status',
]);
const STATIC_CLOUD_KEY =
  /^(AWS_SECRET_ACCESS_KEY|AWS_SECRET_KEY|AZURE_CLIENT_SECRET|ARM_CLIENT_SECRET|GOOGLE_APPLICATION_CREDENTIALS_JSON|GCP_SA_KEY|GCP_CREDENTIALS|GCLOUD_SERVICE_KEY|GOOGLE_CREDENTIALS|[A-Z0-9_]*SERVICE_ACCOUNT_KEY)$/;
