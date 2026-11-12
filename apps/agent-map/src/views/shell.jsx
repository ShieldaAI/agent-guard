import React from 'react';
import { Icon, Notice, Status } from '../components/common.jsx';

export const TABS = Object.freeze([
  ['inventory', 'Agent inventory', 'network'],
  ['owners', 'Owners', 'layers'],
  ['resources', 'Resources', 'search'],
  ['changes', 'Changes', 'clock'],
  ['discovery', 'Discovery', 'fit'],
  ['health', 'Health', 'shield'],
]);
const HEADINGS = Object.freeze({
  inventory: 'Agent inventory',
  owners: 'Agent ownership',
  resources: 'Resource inventory',
  changes: 'What changed',
  discovery: 'Agent discovery',
  health: 'Collection health',
});

export function Topbar({ session, onHome, onLogout }) {
  return (
    <header className="topbar">
      <a
        className="brand"
        href="/"
        onClick={event => {
          event.preventDefault();
          onHome();
        }}
      >
        <span className="brand-mark">
          <Icon name="network" size={22} />
        </span>
        <span>
          Agent Guard <b> / </b>
          <strong>Map</strong>
        </span>
      </a>
      <div className="topbar-right">
        <span className="reference-label">REFERENCE WORKSPACE</span>
        {session && (
          <>
            <Status tone={session.demo ? 'amber' : 'green'}>
              {session.demo ? 'Synthetic demo' : session.company ? 'Company session' : 'Scoped connection'}
            </Status>
            <button className="text-button" onClick={onLogout}>
              <Icon name="logout" size={16} />
              {session.company ? 'Sign out' : 'Disconnect'}
            </button>
          </>
        )}
      </div>
    </header>
  );
}
export function DemoBanner() {
  return (
    <div className="demo-banner">
      <span className="demo-dot" />
      <strong>Demo workspace</strong>
      <span>Synthetic evidence. No executor, cloud account or production service is connected.</span>
    </div>
  );
}
/** Shown a minute before a company session ends, so the reader is not surprised by the sign-in page. */
export function SessionWarning() {
  return (
    <div className="session-warning" role="status">
      Your company session ends in about a minute. You will be asked to sign in again; your place in the map is not kept
      across a new sign-in.
    </div>
  );
}
export function NavTabs({ tab, onTab, onRefresh }) {
  return (
    <nav className="nav-tabs" aria-label="Reference views">
      {TABS.map(([id, title, icon]) => (
        <button
          key={id}
          className={tab === id ? 'active' : ''}
          onClick={() => onTab(id)}
          aria-current={tab === id ? 'page' : undefined}
        >
          <Icon name={icon} size={17} />
          {title}
        </button>
      ))}
      {['inventory', 'health'].includes(tab) && (
        <button className="refresh-button" onClick={onRefresh}>
          <Icon name="refresh" size={16} />
          Refresh evidence
        </button>
      )}
    </nav>
  );
}
export function PageHeading({ tab, matching, sources }) {
  return (
    <div className="page-heading">
      <div>
        <span className="eyebrow">YOUR AUTHORIZED INVENTORY</span>
        <h1>{HEADINGS[tab]}</h1>
        <p>
          {tab === 'inventory'
            ? 'Start with an agent. Explore the relationships that support its declared access.'
            : 'Scope and evidence stay attached to every result.'}
        </p>
      </div>
      <div className="summary-metrics">
        <div>
          <strong>{matching}</strong>
          <span>Matching agents</span>
        </div>
        <div>
          <strong>{sources}</strong>
          <span>Visible sources</span>
        </div>
        <div>
          <strong className="metric-mode">Read only</strong>
          <span>Reference mode</span>
        </div>
      </div>
    </div>
  );
}
/** A short orientation for a first-time reader; closed until asked for. */
export function HelpPanel() {
  return (
    <details className="help-panel">
      <summary>What am I looking at?</summary>
      <div className="help-panel-body">
        <p>
          This map lists the agents that people declared in a host manifest, with the tasks, tools and resources each
          one was granted. An agent nobody declared is not listed here; the Discovery tab shows leads for those.
        </p>
        <dl>
          <div>
            <dt>Exposed</dt>
            <dd>
              One live task can read private data, read outside content and send data out, with nothing declared to stop
              it.
            </dd>
          </div>
          <div>
            <dt>Mitigated</dt>
            <dd>The same three apply, but a declared control (such as required approval) stands in the way.</dd>
          </div>
          <div>
            <dt>Unknown</dt>
            <dd>The declarations do not say enough to rule the combination in or out.</dd>
          </div>
        </dl>
        <p>
          The map never grants or blocks anything. It shows declared and observed evidence; Agent Guard still checks
          every request when it runs.
        </p>
      </div>
    </details>
  );
}
/** A page-level message that stays in view while the reader scrolls. */
export function PageError({ message, onDismiss }) {
  return (
    <div className="page-error sticky-notice">
      <Notice error>{message}</Notice>
      <button className="icon-button" aria-label="Dismiss error" onClick={onDismiss}>
        <Icon name="close" size={16} />
      </button>
    </div>
  );
}
export function Footer() {
  return (
    <footer className="app-footer">
      <span>Agent Guard · Evidence reference</span>
      <span>Declared access is not an execution decision.</span>
    </footer>
  );
}
