import { ASI, rule } from './common.js';
import type { Rule } from './common.js';
import { findHiddenCharacter, lineAt } from '../text.js';

export const INSTRUCTIONS_RULES: readonly Rule[] = [
  rule(
    {
      id: 'AGC-TXT-001',
      title: 'Hidden characters in agent instructions',
      severity: 'medium',
      confidence: 'low',
      owasp: [ASI.goal, ASI.memory],
      help: 'Zero-width, bidirectional and tag characters can hide instructions that a reviewer cannot see but the model reads.',
    },
    (project, report) => {
      for (const file of [...project.prompts, ...project.scripts]) {
        const hidden = findHiddenCharacter(file.text);
        if (hidden)
          report({
            message: `Hidden character ${hidden.codePoint} in ${file.path}.`,
            location: { file: file.path, line: hidden.line },
            subject: 'hidden',
            fix: 'Remove it and review the surrounding text in a hex viewer.',
          });
      }
    },
  ),
  rule(
    {
      id: 'AGC-TXT-002',
      title: 'Instruction-override phrasing in shipped prompts',
      severity: 'medium',
      confidence: 'low',
      owasp: [ASI.goal],
      help: 'Phrases like "ignore previous instructions" or "do not tell the user" are typical of injected text.',
    },
    (project, report) => {
      const pattern =
        /\b(ignore (all |any )?(previous|prior|above|earlier) (instructions|rules|directions)|disregard (all |your |the )?(previous |prior )?(instructions|rules|guidelines)|do not (tell|inform|alert|notify) the user|without (telling|informing|alerting) the user|hide this from the user)\b/i;
      for (const file of project.prompts) {
        const match = pattern.exec(file.text);
        if (match)
          report({
            message: `"${match[0]}" in ${file.path}.`,
            location: { file: file.path, line: lineAt(file.text, match.index) },
            subject: 'override',
            fix: 'Check who added this text and why.',
          });
      }
    },
  ),
  rule(
    {
      id: 'AGC-TXT-003',
      title: 'Long encoded blob in agent instructions',
      severity: 'low',
      confidence: 'low',
      owasp: [ASI.goal],
      help: 'Encoded text cannot be reviewed by reading it, but a model can decode and follow it.',
    },
    (project, report) => {
      for (const file of project.prompts) {
        const match = /(?<!base64,)\b[A-Za-z0-9+/]{200,}={0,2}/.exec(file.text);
        if (match)
          report({
            message: `${match[0].length}-character encoded blob in ${file.path}.`,
            location: { file: file.path, line: lineAt(file.text, match.index) },
            subject: 'blob',
            fix: 'Decode it and review it; keep instructions in plain text.',
          });
      }
    },
  ),
  rule(
    {
      id: 'AGC-TXT-004',
      title: 'Instructions to act without asking',
      severity: 'medium',
      confidence: 'low',
      owasp: [ASI.tools, ASI.trust],
      help: 'Text that tells the agent not to ask for confirmation undermines the approval prompts the config relies on.',
    },
    (project, report) => {
      const pattern =
        /\b(without (asking|requesting|seeking) (for )?(permission|confirmation|approval)|(never|don't|do not) ask (the user )?(for )?(permission|confirmation|approval)|skip (all )?(confirmation|approval)s?)\b/i;
      for (const file of project.prompts) {
        const match = pattern.exec(file.text);
        if (match)
          report({
            message: `"${match[0]}" in ${file.path}.`,
            location: { file: file.path, line: lineAt(file.text, match.index) },
            subject: 'no-ask',
            fix: 'Let the approval settings decide what needs a person, not the prompt.',
          });
      }
    },
  ),
];
