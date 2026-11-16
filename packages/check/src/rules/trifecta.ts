import { ASI, rule } from './common.js';
import type { Rule } from './common.js';
import { CAPABILITY_LABELS } from '../types.js';
import { authority, primaryGrant } from '../authority.js';

export const TRIFECTA_RULES: readonly Rule[] = [
  rule(
    {
      id: 'AGC-TRI-001',
      title: 'Lethal trifecta: private data, untrusted input and an unguarded way out',
      severity: 'critical',
      confidence: 'high',
      owasp: [ASI.goal, ASI.tools],
      help: 'An agent that reads private data and untrusted text, and can send data out without approval, can be steered by that text into leaking the data.',
    },
    (project, report) => {
      for (const agent of project.agents) {
        if (agent.kind === 'subagent') continue;
        const a = authority(agent);
        const legs = [a.privateData, a.untrustedInput, a.egress];
        if (!legs.every(state => state.value === 'yes') || a.egress.approval !== 'auto') continue;
        const way = primaryGrant(a.egress)!;
        report({
          message: `${agent.name} reads private data (${primaryGrant(a.privateData)!.via}), reads untrusted input (${primaryGrant(a.untrustedInput)!.via}) and can send data out without approval (${way.via}).`,
          location: way.location,
          subject: 'trifecta',
          agent,
          fix: `Require approval for "${way.via}", or remove one of the three legs.`,
        });
      }
    },
  ),
  rule(
    {
      id: 'AGC-TRI-002',
      title: 'Lethal trifecta behind one approval, or one leg unknown',
      severity: 'medium',
      confidence: 'high',
      owasp: [ASI.goal],
      help: 'Untrusted input arrives without approval and the agent reads private data; only the approval prompt on sending data out stands in the way, or one leg could not be determined. Approval fatigue makes the first case fragile.',
    },
    (project, report) => {
      for (const agent of project.agents) {
        if (agent.kind === 'subagent') continue;
        const a = authority(agent);
        const legs = { privateData: a.privateData, untrustedInput: a.untrustedInput, egress: a.egress };
        const values = Object.values(legs).map(state => state.value);
        const yes = values.filter(value => value === 'yes').length;
        if (yes === 3 && a.egress.approval === 'ask' && a.untrustedInput.approval === 'auto') {
          const way = primaryGrant(a.egress)!;
          report({
            message: `${agent.name} has all three legs; only the approval prompt for "${way.via}" stands between untrusted input (${primaryGrant(a.untrustedInput)!.via}) and private data (${primaryGrant(a.privateData)!.via}).`,
            location: way.location,
            subject: 'trifecta-ask',
            agent,
            fix: 'Keep that prompt, and remove one leg where you can.',
          });
        } else if (yes === 2 && values.includes('unknown')) {
          const [unknownName, unknown] = Object.entries(legs).find(([, state]) => state.value === 'unknown')!;
          const autoLegs = Object.values(legs)
            .filter(state => state.value === 'yes')
            .every(state => state.approval === 'auto');
          if (unknown.approval !== 'auto' || !autoLegs) continue;
          const grant = primaryGrant(unknown)!;
          report({
            message: `${agent.name} has two legs of the trifecta without approval; whether it also ${CAPABILITY_LABELS[unknownName as 'egress']} through "${grant.via}" is unknown.`,
            location: grant.location,
            subject: `trifecta-unknown:${unknownName}`,
            agent,
            fix: 'Confirm what that path can do; if it can, treat this as AGC-TRI-001.',
          });
        }
      }
    },
  ),
];
