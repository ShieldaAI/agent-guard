import { ASI, IDENTITY_WRITE, SETTINGS_WRITE, allowRules, hooks, rule } from './common.js';
import type { Rule } from './common.js';
import { lineAt } from '../text.js';

export const PERSISTENCE_RULES: readonly Rule[] = [
  rule(
    {
      id: 'AGC-PER-001',
      title: 'Agent can rewrite its own instructions',
      severity: 'high',
      confidence: 'high',
      owasp: [ASI.memory, ASI.rogue],
      help: 'CLAUDE.md, AGENTS.md and memory files are read at every start. Text written there persists across sessions and users.',
    },
    (project, report) => {
      for (const allowed of allowRules(project))
        if (
          ['Edit', 'Write', 'MultiEdit'].includes(allowed.tool) &&
          /(CLAUDE(\.local)?\.md|AGENTS\.md|SOUL\.md|MEMORY\.md)/.test(allowed.specifier ?? '')
        )
          report({
            message: `"${allowed.raw}" lets the agent rewrite its own instruction files without asking.`,
            location: allowed.location,
            subject: allowed.raw,
            fix: 'Remove this allow rule; let a person review instruction changes.',
          });
      for (const hook of hooks(project))
        if (IDENTITY_WRITE.test(hook.command))
          report({
            message: `A ${hook.event} hook writes to an agent instruction file.`,
            location: hook.location,
            subject: `hook:${hook.event}:${hook.command}`,
            fix: 'Write hook output to a log outside the instruction files.',
          });
      for (const file of project.scripts) {
        const match = IDENTITY_WRITE.exec(file.text);
        if (match)
          report({
            message: 'A skill or hook script writes to an agent instruction file.',
            location: { file: file.path, line: lineAt(file.text, match.index) },
            subject: 'script',
            fix: 'Write to a separate file that a person reviews.',
          });
      }
    },
  ),
  rule(
    {
      id: 'AGC-PER-002',
      title: 'Agent can change its own permissions or hooks',
      severity: 'high',
      confidence: 'high',
      owasp: [ASI.rogue],
      help: 'An agent that can edit .claude/settings.json, hooks, agents or skills can grant itself more access.',
    },
    (project, report) => {
      for (const allowed of allowRules(project))
        if (
          ['Edit', 'Write', 'MultiEdit'].includes(allowed.tool) &&
          /\.claude(\/\*\*?|\/?$|\/(settings[^/]*\.json|hooks|agents|skills|commands)\b)/.test(allowed.specifier ?? '')
        )
          report({
            message: `"${allowed.raw}" lets the agent edit its own settings, hooks or skills without asking.`,
            location: allowed.location,
            subject: allowed.raw,
            fix: 'Remove this allow rule and deny Edit(.claude/**).',
          });
      for (const hook of hooks(project))
        if (SETTINGS_WRITE.test(hook.command))
          report({
            message: `A ${hook.event} hook writes into .claude/.`,
            location: hook.location,
            subject: `hook:${hook.event}:${hook.command}`,
            fix: 'Hooks should not modify agent configuration.',
          });
    },
  ),
];
