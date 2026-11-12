// Setup: what this installation is connected to, measured checks and onboarding commands.
import { button, empty, field, node, notice, tag } from '../dom.js';
import { date } from '../text.js';
import { capacityTable } from './shared.js';

const CHECK_LABELS = { passed: 'Ready', attention: 'Needs attention' };
const RECOVERY = {
  'current-state-mirror': [
    'Current-state recovery enrolled',
    'When this service started, both encrypted stores had current-state mirrors and the history mirror was verified. Repair needs the surviving witnesses, mirrors and keys.',
  ],
  'not-enrolled': [
    'Current-state recovery not enrolled',
    'This installation has not enrolled the complete current-state recovery profile. A cold checkpoint becomes stale after any later write, including service startup. The deployment owner must stop the service and enroll mirrors before relying on repair after losing the primary volume.',
  ],
  unverified: [
    'Recovery enrollment not verified here',
    'This service did not report verified recovery enrollment. The deployment owner must check the recovery profile before relying on repair after losing the primary volume.',
  ],
};
const NOT_VERIFIED_HERE = [
  [
    'Backup and restore',
    'Copies of mirrors and witnesses kept elsewhere, a tested repair, backups and access to recovery keys.',
  ],
  ['History and keys', 'Company history files, the backups they depend on and reviewed key retirement.'],
  ['Alerts and ownership', 'Delivered test alerts, named recipients, log retention and an incident owner.'],
  ['Company environment', 'Trusted HTTPS, the real identity provider enrollment and machine sizing.'],
];

export function setupView(ctx) {
  const { state, actions, session } = ctx,
    setup = state.setup;
  if (!ctx.allowed('operator') || !setup)
    return node(
      'section',
      { class: 'panel' },
      empty('Setup unavailable', 'Only operators can open setup. Refresh to check your role.'),
    );
  const [recoveryLabel, recoveryText] = RECOVERY[setup.recovery.mode],
    mirrored = setup.recovery.mode === 'current-state-mirror';
  return node(
    'div',
    { class: 'setup-grid' },
    node(
      'section',
      { class: 'panel' },
      node('div', { class: 'panel-head' }, node('h2', {}, 'Your company workspace')),
      node(
        'div',
        { class: 'panel-body' },
        tag('Self-hosted'),
        node(
          'p',
          { class: 'review-note' },
          'Your deployment keeps the ticket records and encrypted evidence. Company sign-in proves who you are; the service configuration assigns your tenant and roles.',
        ),
        node(
          'dl',
          { class: 'fields receipt' },
          field('Current tenant', session.operator.tenantId, { wide: true }),
          setup.company?.name && field('Company', setup.company.name, { wide: true }),
          setup.company && field('Company identifier', setup.company.id, { wide: true }),
          field('Sign-in provider', node('code', {}, setup.identity.issuer), { wide: true }),
          field('Sign-in return address', node('code', {}, setup.identity.callbackUrl), { wide: true }),
        ),
        node(
          'p',
          { class: 'subtle' },
          'These tickets live in this service. They are not synchronized with Jira, Linear or another ticket system.',
        ),
      ),
    ),
    node(
      'section',
      { class: 'panel' },
      node('div', { class: 'panel-head' }, node('h2', {}, 'Service checks')),
      node(
        'div',
        { class: 'panel-body' },
        node('p', { class: 'subtle' }, 'Measured by the service when this page was loaded. Refresh to measure again.'),
        node(
          'ul',
          { class: 'setup-checks' },
          setup.checks.map(check =>
            node(
              'li',
              {},
              node('div', { class: 'check-title' }, node('strong', {}, check.label), tag(CHECK_LABELS[check.status])),
              node('p', {}, check.message),
            ),
          ),
        ),
      ),
    ),
    node(
      'section',
      { class: 'panel setup-wide' },
      node('div', { class: 'panel-head' }, node('h2', {}, 'Recovery protection')),
      node(
        'div',
        { class: 'panel-body' },
        notice(recoveryLabel, mirrored ? '' : 'warning'),
        node('p', { class: 'review-note' }, recoveryText),
        setup.recovery.verifiedAt !== null &&
          node(
            'dl',
            { class: 'fields receipt' },
            field('Enrollment checked at service startup', date(setup.recovery.verifiedAt), { wide: true }),
          ),
      ),
    ),
    node(
      'section',
      { class: 'panel setup-wide' },
      node('div', { class: 'panel-head' }, node('h2', {}, 'Checks this page cannot make')),
      node(
        'div',
        { class: 'panel-body' },
        notice(
          'The deployment owner must confirm these outside this page before the service runs unattended.',
          'warning',
        ),
        node(
          'ul',
          { class: 'setup-checks' },
          NOT_VERIFIED_HERE.map(([label, message]) =>
            node(
              'li',
              {},
              node('div', { class: 'check-title' }, node('strong', {}, label), tag('Not verified here')),
              node('p', {}, message),
            ),
          ),
        ),
      ),
    ),
    node(
      'section',
      { class: 'panel setup-wide' },
      node('div', { class: 'panel-head' }, node('h2', {}, 'Capacity limits')),
      node(
        'div',
        { class: 'panel-body' },
        capacityTable(setup),
        node(
          'p',
          { class: 'subtle' },
          'Usage is from the last refresh. Limits are read-only here; changing them needs the offline configuration commands and a restart.',
        ),
      ),
    ),
    node(
      'section',
      { class: 'panel setup-wide' },
      node(
        'div',
        { class: 'panel-head' },
        node(
          'div',
          {},
          node('h2', {}, 'Onboarding commands'),
          node('p', {}, 'Run these on the deployment machine with the private configuration.'),
        ),
      ),
      node(
        'div',
        { class: 'panel-body' },
        setup.data.tickets === 0 &&
          notice(
            'No company tickets are enrolled in this tenant. Import reviewed ticket data before preparing changes.',
            'warning',
          ),
        node(
          'p',
          { class: 'subtle' },
          'Stop the service first: these commands need exclusive access to the stores. Replace the example paths. Review each preview before applying it. Nothing runs from this page.',
        ),
        node(
          'ol',
          { class: 'setup-commands' },
          setup.commands.map(command =>
            node('li', {}, node('h3', {}, command.label), node('pre', {}, node('code', {}, command.command))),
          ),
        ),
        node(
          'p',
          { class: 'review-note' },
          'TLS keys, the sign-in client secret, agent tokens and store keys stay in files on the deployment machine. This page never asks for or shows them.',
        ),
        button('View tickets', () => actions.navigate('tickets')),
      ),
    ),
  );
}
