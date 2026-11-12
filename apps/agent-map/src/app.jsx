import React, { useLayoutEffect, useRef } from 'react';
import { createRoot } from 'react-dom/client';
import { useWorkspace } from './hooks/use-workspace.mjs';
import { Empty, Notice } from './components/common.jsx';
import { SignIn } from './views/sign-in.jsx';
import {
  DemoBanner,
  Footer,
  HelpPanel,
  NavTabs,
  PageError,
  PageHeading,
  SessionWarning,
  Topbar,
} from './views/shell.jsx';
import { AgentSidebar } from './views/agent-sidebar.jsx';
import { AgentDetail } from './views/agent-detail.jsx';
import { OwnersBrowse } from './views/owners.jsx';
import { ResourcesBrowse } from './views/resources.jsx';
import { ChangesView } from './views/changes.jsx';
import { Health, HealthUnavailable } from './views/health.jsx';
import { DiscoveryView } from './discovery.jsx';
import './style.css';

/** Shown in place of an agent until one is chosen. */
function Welcome({ listingFailed }) {
  return listingFailed ? (
    <div className="welcome-card">
      <Empty title="Refresh inventory to continue">
        Select Refresh evidence to load agents for your current filters.
      </Empty>
    </div>
  ) : (
    <div className="welcome-card">
      <Empty title="Choose an agent to explore">
        Select an agent from your visible inventory to inspect its tasks, declared grants, MCP connections and cloud
        associations.
      </Empty>
      <div className="welcome-principles">
        <div>
          <span>01</span>
          <h3>Follow relationships</h3>
          <p>Start with one focused neighborhood.</p>
        </div>
        <div>
          <span>02</span>
          <h3>Inspect the evidence</h3>
          <p>Keep declared and observed state distinct.</p>
        </div>
        <div>
          <span>03</span>
          <h3>Keep unknowns visible</h3>
          <p>A map does not authorize execution.</p>
        </div>
      </div>
    </div>
  );
}

/** The page: sign-in, or the open workspace with its six views. The state is in `useWorkspace`. */
function App() {
  const view = useWorkspace();
  const {
    connection: workspace,
    session,
    reportError,
    tab,
    filters,
    selected,
    listing,
    options,
    health,
    sources,
  } = view;
  const { resourceOwner, resourceSelection, selectAgent, showResource, covered } = view;
  // The element inside the workspace that holds keyboard focus, if any.
  const focused = useRef(null),
    covering = useRef(false);
  // A covered workspace keeps its layout (so the scroll position stays) but is not shown, not
  // read out and not operable. Covering it takes keyboard focus away; it goes back once the
  // session check passes.
  covering.current = covered;
  // Where the page was scrolled when the cover went on. It is put back after focus returns:
  // some browsers (WebKit on Linux) scroll to a focused element despite `preventScroll`.
  const coveredAt = useRef(null);
  useLayoutEffect(() => {
    if (covered) {
      coveredAt.current = [window.scrollX, window.scrollY];
      return;
    }
    const previous = focused.current;
    // Not when the reader has moved focus elsewhere meanwhile, or the element is gone.
    if (previous?.isConnected && (!document.activeElement || document.activeElement === document.body))
      previous.focus({ preventScroll: true });
    else focused.current = null;
    const place = coveredAt.current;
    coveredAt.current = null;
    if (place && (window.scrollX !== place[0] || window.scrollY !== place[1])) window.scrollTo(place[0], place[1]);
  }, [covered]);
  const query = session?.query;
  return (
    <div className="app">
      <Topbar session={session} onHome={view.showHome} onLogout={workspace.logout} />
      {!session ? (
        <SignIn
          authentication={workspace.authentication}
          credential={workspace.credential}
          onCredential={workspace.setCredential}
          connecting={workspace.connecting}
          error={workspace.error}
          onConnect={workspace.connect}
          onSignIn={workspace.signIn}
          onLogout={workspace.logout}
          onCheck={workspace.checkSignIn}
          onDemo={event => workspace.connect(event, true)}
        />
      ) : (
        <>
          {session.demo && <DemoBanner />}
          {workspace.expiring && <SessionWarning />}
          <NavTabs tab={tab} onTab={view.openTab} onRefresh={view.refresh} />
          {/* Always present, so the message is announced when it appears; it is drawn over the covered workspace. */}
          <p className="session-check" role="status">
            {workspace.checking ? 'Checking your session…' : ''}
          </p>
          {/* Keyed by the workspace: a different session gets new views, and none keeps what an earlier one read. */}
          <main
            key={session.serial}
            className={`workspace${covered ? ' covered' : ''}`}
            inert={covered}
            aria-hidden={covered || undefined}
            onFocus={event => {
              focused.current = event.target;
            }}
            onBlur={() => {
              // Covering the workspace blurs the focused element; that one is remembered.
              if (!covering.current) focused.current = null;
            }}
          >
            <PageHeading
              tab={tab}
              matching={listing.state === 'ready' ? String(listing.page.total ?? listing.agents.length) : '—'}
              sources={health.status === 'ready' || sources.length ? sources.length : '—'}
            />
            {workspace.error && <PageError message={workspace.error} onDismiss={() => workspace.setError('')} />}
            {['changes', 'discovery', 'health'].includes(tab) && (
              <HealthUnavailable health={health} onRetry={view.retryHealth} />
            )}
            {tab === 'inventory' ? (
              <>
                <HelpPanel />
                <div className="inventory-layout">
                  <AgentSidebar
                    listing={listing}
                    filters={filters}
                    onFilter={view.setFilter}
                    onClearOwner={() => view.setFilter('owner', '')}
                    options={options}
                    selection={selected.selection}
                    onSelect={selectAgent}
                    onPage={view.setOffset}
                  />
                  <div className="agent-content">
                    {selected.error && <Notice error>This agent could not be opened. {selected.error}</Notice>}
                    {selected.busy ? (
                      <div className="loading" role="status">
                        <span className="spinner" />
                        Loading scoped evidence…
                      </div>
                    ) : selected.access ? (
                      <AgentDetail
                        key={`${selected.access.data.agent.sourceId}:${selected.access.data.agent.id}`}
                        response={selected.access}
                        query={query}
                        reportError={reportError}
                        onAgent={selectAgent}
                        onResource={showResource}
                        focusHeading={selected.focusRequest}
                      />
                    ) : (
                      <Welcome listingFailed={listing.state === 'error'} />
                    )}
                  </div>
                </div>
              </>
            ) : tab === 'owners' ? (
              <OwnersBrowse
                query={query}
                reportError={reportError}
                onOwner={view.showOwner}
                onOwnerResources={view.showOwnerResources}
              />
            ) : tab === 'resources' ? (
              <ResourcesBrowse
                key={
                  resourceSelection
                    ? `resource:${resourceSelection.sourceId}:${resourceSelection.id}`
                    : resourceOwner
                      ? `owner:${resourceOwner.sourceId}:${resourceOwner.ownerId}`
                      : 'all'
                }
                query={query}
                reportError={reportError}
                onAgent={selectAgent}
                ownerFilter={resourceOwner}
                initialResource={resourceSelection}
              />
            ) : tab === 'changes' ? (
              <ChangesView sources={sources} query={query} reportError={reportError} onAgent={selectAgent} />
            ) : tab === 'discovery' ? (
              <DiscoveryView sources={sources} query={query} reportError={reportError} />
            ) : (
              <Health sources={sources} status={health.status} />
            )}
          </main>
          <Footer />
        </>
      )}
    </div>
  );
}
createRoot(document.getElementById('root')).render(<App />);
