import React from 'react';
import { Icon, Notice } from '../components/common.jsx';

/** The first screen: a reference credential, a company sign-in, or the local synthetic demo. */
export function SignIn({
  authentication,
  credential,
  onCredential,
  connecting,
  error,
  onConnect,
  onSignIn,
  onLogout,
  onCheck,
  onDemo,
}) {
  const mode = authentication.mode;
  return (
    <main className="login-layout">
      <section className="login-intro">
        <span className="eyebrow">THE AGENT REFERENCE MAP</span>
        <h1>
          Understand your agents.
          <br />
          <span>Follow the evidence.</span>
        </h1>
        <p>
          Explore agents, declared grants and their connected systems in one scoped view. See what is observed, what has
          changed and what remains unknown.
        </p>
        <div className="intro-features">
          <div>
            <Icon name="network" />
            <span>Focused relationships</span>
          </div>
          <div>
            <Icon name="shield" />
            <span>Read-only reference</span>
          </div>
          <div>
            <Icon name="clock" />
            <span>Independent capture times</span>
          </div>
        </div>
        <div className="intro-diagram" aria-hidden="true">
          <span>Agent</span>
          <i />
          <span>Task</span>
          <i />
          <span>Declared grant</span>
          <i />
          <span>Resource</span>
        </div>
      </section>
      <section className="login-card">
        <span className="login-icon">
          <Icon name="lock" size={24} />
        </span>
        <h2>Connect to your inventory</h2>
        {mode === 'bearer' ? (
          <>
            <p>
              Use a reference credential issued by your host administrator. Your company and team scope is set by the
              service.
            </p>
            <form onSubmit={onConnect}>
              <label>
                Reference credential
                <input
                  type="password"
                  autoComplete="off"
                  spellCheck={false}
                  required
                  value={credential}
                  onChange={event => onCredential(event.target.value)}
                  placeholder="agm_v1.…"
                  maxLength={128}
                />
              </label>
              <button className="primary-button full" disabled={connecting}>
                {connecting ? 'Connecting…' : 'Open agent map'}
                <Icon name="arrow" />
              </button>
            </form>
            <p className="credential-note">
              The credential stays in memory for this page. It is never saved in browser storage.
            </p>
          </>
        ) : mode === 'oidc' ? (
          <>
            <p>
              Sign in with your company account. Your access to agents and teams is assigned by the host administrator.
            </p>
            <button className="primary-button full" onClick={onSignIn} disabled={connecting}>
              {connecting
                ? 'Connecting…'
                : authentication.authenticated
                  ? 'Open company map'
                  : 'Sign in with company account'}
              <Icon name="arrow" />
            </button>
            <p className="credential-note">
              Your sign-in credentials stay with your identity provider. This page receives a scoped browser session.
            </p>
          </>
        ) : mode === 'pending' || mode === 'signing-out' ? (
          <p role="status">{mode === 'pending' ? 'Checking sign-in settings…' : 'Signing out…'}</p>
        ) : (
          <button
            className="primary-button full"
            onClick={mode === 'logout-unconfirmed' ? onLogout : onCheck}
            disabled={connecting}
          >
            {mode === 'logout-unconfirmed' ? 'Retry sign out' : 'Check sign-in'}
            <Icon name="arrow" />
          </button>
        )}
        {error && <Notice error>{error}</Notice>}
        <div className="demo-divider">
          <span>or explore the interface</span>
        </div>
        <button className="secondary-button full" onClick={onDemo} disabled={mode === 'signing-out'}>
          Open synthetic demo
        </button>
        <p className="demo-note">Demo data is local to this page and is not live inventory.</p>
      </section>
    </main>
  );
}
