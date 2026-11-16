import { ASI, PLACEHOLDER, agentServers, knownToken, literalSecret, rule, serverLabel } from './common.js';
import type { Rule } from './common.js';
import type { Location } from '../types.js';
import { lineAt, mask } from '../text.js';

export const SECRETS_RULES: readonly Rule[] = [
  rule(
    {
      id: 'AGC-SEC-001',
      title: 'Hardcoded credential',
      severity: 'critical',
      confidence: 'high',
      owasp: [ASI.identity],
      help: 'Credentials in committed agent config are readable by everyone with repo access and by the agent itself.',
    },
    (project, report) => {
      const leak = (label: string, name: string, value: string, location: Location, subject: string) =>
        report({
          message: `${label} in ${name}: ${mask(value)}.`,
          location,
          subject,
          fix: 'Revoke it, then read it from the environment or a secret store, for example "${API_TOKEN}".',
        });
      for (const server of agentServers(project)) {
        for (const [name, value] of [...Object.entries(server.env), ...Object.entries(server.headers)]) {
          const label = literalSecret(name, value);
          if (label)
            leak(
              label,
              `${serverLabel(server)} ${name}`,
              value.replace(/^(Bearer|Basic|token)\s+/i, ''),
              server.location,
              `server:${server.name}:${name}`,
            );
        }
        for (const arg of server.args) {
          const token = knownToken(arg);
          if (token)
            leak(
              token.label,
              `${serverLabel(server)} arguments`,
              token.value,
              server.location,
              `server:${server.name}:arg`,
            );
        }
      }
      for (const file of project.settings)
        for (const item of file.env) {
          const label = literalSecret(item.name, item.value);
          if (label) leak(label, `settings env ${item.name}`, item.value, item.location, `env:${item.name}`);
        }
      for (const step of project.workflows)
        for (const input of step.literalInputs) {
          const label = literalSecret(input.key, input.value);
          if (label)
            leak(label, `workflow input ${input.key}`, input.value, input.location, `input:${step.job}:${input.key}`);
        }
      for (const file of [...project.prompts, ...project.scripts]) {
        const token = knownToken(file.text);
        if (token)
          leak(token.label, file.path, token.value, { file: file.path, line: lineAt(file.text, token.index) }, 'text');
      }
    },
  ),
  rule(
    {
      id: 'AGC-SEC-002',
      title: 'Secret passed on a command line',
      severity: 'medium',
      confidence: 'high',
      owasp: [ASI.identity],
      help: 'Command-line arguments are visible to every process on the machine and often end up in logs.',
    },
    (project, report) => {
      for (const server of agentServers(project)) {
        server.args.forEach((arg, index) => {
          const inline = /^--?(token|api-?key|password|secret|access-token|auth)=(.+)$/i.exec(arg);
          const flag = /^--?(token|api-?key|password|secret|access-token|auth)$/i.test(arg);
          const value = inline?.[2] ?? (flag ? server.args[index + 1] : undefined);
          if (!value || PLACEHOLDER.test(value) || knownToken(value)) return;
          report({
            message: `${serverLabel(server)} receives a secret as a command-line argument (${inline?.[1] ?? arg.replace(/^-+/, '')}).`,
            location: server.location,
            subject: `server:${server.name}:${index}`,
            fix: 'Pass it through env instead.',
          });
        });
      }
    },
  ),
];
