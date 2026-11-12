// The page before sign-in and after a session ended.
import { button, node, notice } from '../dom.js';

export function loginView({ phase, error, actions }) {
  let control;
  if (phase === 'checking' || phase === 'signing-out')
    control = node('p', { class: 'subtle' }, phase === 'checking' ? 'Checking your session…' : 'Signing out…');
  else if (phase === 'logout-unconfirmed')
    control = button('Retry sign out', actions.signOut, { id: 'retry-sign-out' });
  else
    control = button(phase === 'ended' ? 'Sign in again' : 'Sign in with company account', actions.signIn, {
      primary: true,
      id: 'sign-in',
    });
  return node(
    'main',
    { id: 'main', class: 'login', tabindex: '-1' },
    node(
      'section',
      { class: 'login-intro' },
      node('span', { class: 'eyebrow' }, 'Review workspace'),
      node('h1', {}, 'Review the change.', node('br'), 'Know the outcome.'),
      node(
        'p',
        {},
        'See exactly what an agent or a colleague wants to change, approve or deny it, and follow it until it is confirmed.',
      ),
    ),
    node(
      'section',
      { class: 'panel login-card' },
      node('h2', { id: 'login-heading', tabindex: '-1' }, phase === 'ended' ? 'You are signed out' : 'Sign in'),
      node('p', {}, 'Use your company account. Your tenant and roles come from the service configuration.'),
      error && notice(error, 'error', 'error-notice'),
      control,
      node('p', { class: 'session-footnote' }, 'Your company identity provider handles sign-in.'),
    ),
  );
}
