import React, { useCallback, useEffect, useRef, useState } from 'react';
import { createRoot } from 'react-dom/client';
import cytoscape from 'cytoscape';
import { agentOptions, componentHealth, createCompanyQuerySession, createQuerySession, endCompanySession, readCompanySession, retryCompanyLogout, startCompanyLogin, watchCompanySession, displayTime, errorMessage, evidenceState, graphElements, initialExplanation, kindName, nodeName, queryReference, shortReference } from './view-model.mjs';
import { queryDemo } from './demo.mjs';
import { PolicyEvidence } from './policy-evidence.jsx';
import './style.css';

function Icon({ name, size = 18 }) {
  const paths = { search: 'M21 21l-5.5-5.5M18 10.5a7.5 7.5 0 1 1-15 0 7.5 7.5 0 0 1 15 0',
    network: 'M6 5h12M6 19h12M5 6v12M19 6v12M7 7l10 10M17 7L7 17',
    layers: 'M12 3l10 6-10 6L2 9l10-6M2 14l10 6 10-6',
    clock: 'M12 8v5l3 2M22 12a10 10 0 1 1-20 0 10 10 0 0 1 20 0',
    arrow: 'M5 12h14M13 6l6 6-6 6', refresh: 'M20 7V2l-3 3a9 9 0 1 0 3 13M20 2h-5',
    close: 'M6 6l12 12M18 6L6 18', lock: 'M6 10h12v11H6V10M8 10V6a4 4 0 0 1 8 0v4',
    fit: 'M8 3H3v5M16 3h5v5M21 16v5h-5M8 21H3v-5', shield: 'M12 2l8 3v6c0 5-4 9-8 11-4-2-8-6-8-11V5l8-3M8 12l3 3 5-6',
    logout: 'M9 4H4v16h5M10 12h11M16 7l5 5-5 5' };
  return <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true"><path d={paths[name] ?? paths.network}/></svg>;
}
function Status({ children, tone = 'neutral' }) { return <span className={`status ${tone}`}><span className="status-dot"/>{children}</span>; }
function Notice({ children, error = false }) { return <div className={`notice ${error ? 'error' : ''}`} role={error ? 'alert' : undefined}>{children}</div>; }
function Empty({ title, children }) { return <div className="empty"><span className="empty-icon"><Icon name="network" size={30}/></span><h3>{title}</h3><p>{children}</p></div>; }

function Graph({ graph, policyEvidence, onSelect }) {
  const container = useRef(null), instance = useRef(null);
  const [labels, setLabels] = useState(true), [error, setError] = useState('');
  useEffect(() => {
    setError('');
    let elements;
    try { elements = graphElements(graph, policyEvidence); } catch { setError('This graph could not be displayed safely. Select another agent.'); return; }
    const cy = cytoscape({ container: container.current, elements, minZoom: .25, maxZoom: 2.5,
      layout: { name: 'breadthfirst', directed: false, padding: 45, spacingFactor: 1.15, avoidOverlap: true },
      style: [
        { selector: 'node', style: { 'background-color': '#e8edf4', 'border-width': 1.5, 'border-color': '#b6c5d7', 'width': 38, 'height': 38,
          'label': 'data(label)', 'font-size': 10, 'font-family': 'Inter, system-ui, sans-serif', 'color': '#314358', 'text-valign': 'bottom', 'text-margin-y': 9,
          'text-wrap': 'ellipsis', 'text-max-width': 130, 'text-background-color': '#f9fbfd', 'text-background-opacity': .85, 'text-background-padding': 2 } },
        { selector: 'node.agent', style: { 'background-color': '#274b77', 'border-color': '#183b65', 'width': 52, 'height': 52, 'color': '#173754', 'font-weight': 600 } },
        { selector: 'node.task', style: { 'background-color': '#dcecf7', 'border-color': '#78a6c8', 'shape': 'round-rectangle' } },
        { selector: 'node.resource', style: { 'background-color': '#e1ede6', 'border-color': '#86ab96', 'shape': 'round-rectangle' } },
        { selector: 'node.mcp', style: { 'background-color': '#e9e3f5', 'border-color': '#ab99c9', 'shape': 'hexagon' } },
        { selector: 'node.identity', style: { 'background-color': '#f5ead7', 'border-color': '#c6a36c', 'shape': 'diamond', 'width': 43, 'height': 43 } },
        { selector: 'node.unavailable', style: { 'border-style': 'dashed', 'border-color': '#bd923e', 'background-color': '#fbf3df' } },
        { selector: 'node.conditional', style: { 'border-style': 'dotted', 'border-width': 3, 'border-color': '#ac863d' } },
        { selector: 'node.blocked', style: { 'background-color': '#f9e1df', 'border-color': '#c66d66' } },
        { selector: 'node:selected', style: { 'border-width': 3.5, 'border-color': '#2b77be', 'overlay-opacity': 0 } },
        { selector: 'edge', style: { 'width': 1.4, 'line-color': '#b5c3d2', 'target-arrow-color': '#a2b2c5', 'target-arrow-shape': 'triangle', 'arrow-scale': .65,
          'curve-style': 'bezier', 'label': 'data(label)', 'font-size': 8, 'color': '#6d7c8d', 'text-rotation': 'autorotate', 'text-background-color': '#f9fbfd', 'text-background-opacity': .9, 'text-background-padding': 3 } },
        { selector: 'edge.association', style: { 'line-style': 'dashed', 'line-color': '#c0a77d', 'target-arrow-color': '#c0a77d' } },
        { selector: 'edge.unavailable', style: { 'line-style': 'dashed', 'line-color': '#b9934e', 'target-arrow-color': '#b9934e' } },
        { selector: 'edge.conditional', style: { 'line-style': 'dotted', 'line-color': '#ac863d', 'target-arrow-color': '#ac863d' } },
        { selector: 'edge.policy-candidate', style: { 'line-style': 'dashed', 'line-color': '#a37834', 'target-arrow-color': '#a37834', 'width': 2, 'color': '#85632e' } },
      ] });
    instance.current = cy;
    cy.on('tap', 'node', event => onSelect(event.target.data('source')));
    const resize = new ResizeObserver(() => { cy.resize(); cy.fit(undefined, 40); });
    resize.observe(container.current);
    return () => { resize.disconnect(); cy.destroy(); instance.current = null; };
  }, [graph, policyEvidence, onSelect]);
  useEffect(() => { instance.current?.style().selector('node, edge').style('label', labels ? 'data(label)' : '').update(); }, [labels, graph]);
  return <div className="graph-shell">
    <div className="graph-tools"><span>FOCUSED NEIGHBORHOOD</span><div>
      <button className="small-button" onClick={() => setLabels(!labels)} aria-pressed={labels}>Labels {labels ? 'on' : 'off'}</button>
      <button className="icon-button" title="Fit graph" aria-label="Fit graph" onClick={() => instance.current?.fit(undefined, 40)}><Icon name="fit" size={16}/></button>
    </div></div>
    <div className="graph" ref={container} role="img" aria-label="Agent evidence network. Use the evidence list below for accessible node selection."/>
    {error && <div className="graph-error"><Notice error>{error}</Notice></div>}
    <div className="graph-legend"><span><i className="legend-agent"/>Agent</span><span><i className="legend-task"/>Task</span><span><i className="legend-mcp"/>MCP</span><span><i className="legend-resource"/>Resource</span><span><i className="legend-unknown"/>Unknown / unavailable</span><span><i className="legend-conditional"/>Conditional</span><span><i className="legend-policy"/>Policy candidate · access unknown</span></div>
  </div>;
}

function Evidence({ node, graph, select }) {
  const nodes = graph?.nodes ?? [];
  const state = evidenceState(node);
  return <section className="evidence-panel">
    <div className="section-heading"><h3>Evidence detail</h3><Icon name="layers" size={17}/></div>
    <label className="field-label" htmlFor="evidence-node">Select a node</label>
    <select id="evidence-node" value={node?.id ?? ''} onChange={event => select(nodes.find(item => item.id === event.target.value) ?? null)}>
      <option value="">Choose from the graph</option>{nodes.map(item => <option key={item.id} value={item.id}>{kindName(item.label)} · {nodeName(item)}</option>)}
    </select>
    {node ? <><span className="eyebrow node-type">{kindName(node.label)}</span><h4 className="node-name">{nodeName(node)}</h4>
      <Status tone={state.kind === 'blocked' ? 'danger' : ['unavailable', 'conditional', 'unknown'].includes(state.kind) ? 'amber' : 'neutral'}>{state.label}</Status>
      <dl className="property-list">{Object.entries(node.properties ?? {}).filter(([key]) => !['id', 'projection_id', 'source_id', 'entity_id'].includes(key)).map(([key, value]) =>
        <div key={key}><dt>{key.replaceAll('_', ' ')}</dt><dd>{value === null ? 'Unknown' : Array.isArray(value) ? value.join(', ') : typeof value === 'object' ? JSON.stringify(value) : String(value)}</dd></div>)}</dl>
    </> : <p className="subtle evidence-hint">Select a node to inspect its captured state, scope and supporting evidence.</p>}
    <div className="evidence-footnote"><Icon name="shield" size={16}/><p>This map explains collected evidence. Agent Guard still checks each execution request.</p></div>
  </section>;
}

function Explain({ access, graph, query, reportError }) {
  const [form, setForm] = useState(() => initialExplanation(access)), [result, setResult] = useState(null), [busy, setBusy] = useState(false);
  useEffect(() => { setForm(initialExplanation(access)); setResult(null); }, [access]);
  async function submit(event) {
    event.preventDefault(); setBusy(true); setResult(null);
    try { setResult((await query('explain_access', { sourceId: access.agent.sourceId, ...form })).data); }
    catch (error) { reportError(error); } finally { setBusy(false); }
  }
  return <section className="explanation-card">
    <div className="section-heading"><div><h3>Explain declared access</h3><p>Inspect one task, tool and exported resource selector.</p></div><span className="pill">Read only</span></div>
    <form onSubmit={submit} className="explain-form">
      <label>Task<select value={form.taskId} required onChange={event => setForm({ ...form, taskId: event.target.value })}><option value="">Select task</option>{(access.tasks ?? []).map(task => <option key={task.id} value={task.taskId}>{task.taskId}</option>)}</select></label>
      <label>Tool<input value={form.tool} maxLength={4096} required onChange={event => setForm({ ...form, tool: event.target.value })} placeholder="Registered tool name"/></label>
      <label>Resource selector<input value={form.resourceId} maxLength={4096} required onChange={event => setForm({ ...form, resourceId: event.target.value })} placeholder="Exact exported reference"/></label>
      <button className="primary-button" disabled={busy || !form.taskId}>{busy ? 'Checking…' : 'Explain'}<Icon name="arrow" size={16}/></button>
    </form>
    {result && <div className="explanation-result" role="status"><Status tone={result.assessment === 'blocked' ? 'danger' : 'amber'}>{result.assessment === 'blocked' ? 'Observed blocker' : 'Execution remains unknown'}</Status>
      {result.blockers?.length > 0 && <div><h4>Known blockers</h4><ul>{result.blockers.map((item, i) => <li key={i}>{typeof item === 'string' ? item.replaceAll('_', ' ') : JSON.stringify(item)}</li>)}</ul></div>}
      {result.unknownChecks?.length > 0 && <div><h4>Still requires evaluation</h4><ul>{result.unknownChecks.map((item, i) => <li key={i}>{typeof item === 'string' ? item.replaceAll('_', ' ') : JSON.stringify(item)}</li>)}</ul></div>}
      <p className="subtle">No action was prepared or executed.</p>
      <PolicyEvidence evidence={result.externalEvidence?.policyEvidence} graph={graph}/></div>}
  </section>;
}

function ResourceLookup({ query, onAgent, reportError }) {
  const [resourceRef, setResource] = useState(''), [action, setAction] = useState('s3:GetObject'), [result, setResult] = useState(null), [busy, setBusy] = useState(false);
  async function submit(event) { event.preventDefault(); setBusy(true); setResult(null);
    try { setResult((await query('find_agents_with_access', { resourceRef, action })).data); }
    catch (error) { reportError(error); } finally { setBusy(false); } }
  const candidates = result?.candidates ?? result?.agents ?? [];
  return <section className="wide-card"><div className="section-heading"><div><h2>Find potential access</h2><p>Match an exact resource reference and declared cloud action in your visible inventory.</p></div><Icon name="search" size={24}/></div>
    <form className="resource-form" onSubmit={submit}><label>Resource reference<input value={resourceRef} onChange={event => setResource(event.target.value)} required maxLength={4096} placeholder="Exported resource reference or canonical ARN"/></label><label>Action<input value={action} onChange={event => setAction(event.target.value)} required maxLength={256} placeholder="s3:GetObject"/></label><button className="primary-button" disabled={busy}>{busy ? 'Searching…' : 'Find candidates'}<Icon name="arrow" size={16}/></button></form>
    <Notice>Results describe potential access through declared grants and explicit mappings. They do not establish effective cloud permission.</Notice>
    {result ? candidates.length ? <div className="candidate-list">{candidates.map((candidate, i) => { const agent = candidate.agent ?? candidate; return <article className="candidate-result" key={`${agent.id ?? i}-${i}`}><button className="candidate" onClick={() => onAgent(agent)}><div className="agent-avatar"><Icon name="network"/></div><div><h3>{agent.name ?? agent.agentId ?? 'Candidate agent'}</h3><p>{candidate.scope ? `${candidate.scope} scope · ` : ''}{agent.teamId ?? 'Unassigned team'}</p></div><Status tone="amber">Potential access</Status><Icon name="arrow"/></button><PolicyEvidence compact evidence={Array.isArray(candidate.evidence) ? candidate.evidence.flatMap(item => item.policyEvidence ?? []) : []}/></article>; })}</div> : <Empty title="No matching candidates">No visible mapping matched this reference and action. This does not prove access is denied.</Empty> : <Empty title="Start with a resource">Use an exact reference from a host binding or from an agent’s evidence panel.</Empty>}
  </section>;
}

function Changes({ sources, query, reportError }) {
  const [sourceId, setSource] = useState(sources[0]?.id ?? sources[0]?.sourceId ?? ''), [result, setResult] = useState(null), [busy, setBusy] = useState(false);
  async function compare(event) { event.preventDefault(); setBusy(true); setResult(null);
    try { setResult((await query('get_changes', { sourceId, since: 'previous' })).data); }
    catch (error) { reportError(error); } finally { setBusy(false); } }
  return <section className="wide-card"><div className="section-heading"><div><h2>Snapshot comparison</h2><p>Compare the current published view with its retained predecessor.</p></div><Icon name="clock" size={25}/></div>
    <form className="comparison-form" onSubmit={compare}><label>Authorized source<select value={sourceId} onChange={event => setSource(event.target.value)} required><option value="">Select a source</option>{sources.map(source => <option key={source.id ?? source.sourceId} value={source.id ?? source.sourceId}>{source.tenantId} · {shortReference(source.sourceId ?? source.id)}</option>)}</select></label><button className="primary-button" disabled={busy || !sourceId}>{busy ? 'Comparing…' : 'Compare snapshots'}<Icon name="arrow" size={16}/></button></form>
    {result ? <>{result.coverageGap && <Notice>A comparison baseline is unavailable in the retained, authorized inventory. No complete change history can be inferred.</Notice>}
      <div className="comparison-times"><span>Previous <strong>{displayTime(result.from?.generatedAt)}</strong></span><Icon name="arrow"/><span>Current <strong>{displayTime(result.to?.generatedAt)}</strong></span></div>
      <div className="change-columns">{['added', 'changed', 'removed'].map(kind => <section key={kind}><h3><span className={`change-dot ${kind}`}/>{kind}<span className="count">{result.changes?.[kind]?.length ?? 0}</span></h3>{result.changes?.[kind]?.length ? <ul>{result.changes[kind].map((item, i) => <li key={item.entityId ?? i}><span>{item.name ?? shortReference(item.entityId)}</span><small>{kindName(item.label)}</small></li>)}</ul> : <p className="subtle">No visible {kind} items.</p>}</section>)}</div>
      <p className="fine-print">These are net changes between visible snapshots, not a record of every intermediate grant or invocation. IAM policy history is not collected; current policy candidates are not compared here.</p></> : <Empty title="Compare collected evidence">Only published snapshots within your authorization scope are included.</Empty>}
  </section>;
}

function Health({ sources }) {
  return <section className="wide-card"><div className="section-heading"><div><h2>Inventory health</h2><p>Capture freshness and collection coverage for your authorized sources.</p></div><Icon name="shield" size={25}/></div>
    {sources.length ? <div className="health-list">{sources.map(source => <article className="health-item" key={source.id ?? source.sourceId}><div><h3>{source.tenantId ?? 'Authorized source'}</h3><code>{shortReference(source.sourceId ?? source.id)}</code></div><div><span className="field-label">Snapshot captured</span><strong>{displayTime(source.generatedAt)}</strong></div><Status tone={source.stale === false ? 'green' : 'amber'}>{source.stale === false ? 'Snapshot recent' : 'Snapshot stale'}</Status><div className="coverage-list">{Object.entries(source.coverage ?? {}).map(([component, coverage]) => {
      const state = componentHealth(coverage);
      return <section className="coverage-item" key={component} aria-label={`${component} collection`}><div><b>{component}</b><span>{state.status}</span></div><time dateTime={state.observedAt ?? undefined}>{state.observedLabel}</time><Status tone={state.tone}>{state.freshness}</Status>{state.ageLabel && <small>{state.ageLabel}</small>}</section>;
    })}</div></article>)}</div> : <Empty title="No visible sources">No published source is available in your current scope.</Empty>}
    <Notice>Recent collection does not establish current execution permission. Provider and MCP observations have independent lifecycles.</Notice>
  </section>;
}

function App() {
  const [session, setSession] = useState(null), [credential, setCredential] = useState(''), [connecting, setConnecting] = useState(false);
  const [tab, setTab] = useState('inventory'), [agents, setAgents] = useState([]), [sources, setSources] = useState([]), [truncated, setTruncated] = useState(false);
  const [search, setSearch] = useState(''), [owner, setOwner] = useState(''), [environment, setEnvironment] = useState(''), [options, setOptions] = useState({ owners: [], environments: [] });
  const [selection, setSelection] = useState(null), [access, setAccess] = useState(null), [node, setNode] = useState(null), [busy, setBusy] = useState(false), [error, setError] = useState('');
  const [authentication, setAuthentication] = useState({ mode: 'pending' });
  const generation = useRef(0), authenticationGeneration = useRef(0);
  const pendingConnection = useRef(null), activeSession = useRef(null), authenticationRequest = useRef(null);
  const auth = useRef(authentication), logoutToken = useRef(null);
  auth.current = authentication;
  const query = useCallback((operation, args) => session.query(operation, args), [session]);
  const selectNode = useCallback(value => setNode(value), []);
  const clearWorkspace = useCallback(() => {
    activeSession.current?.close(); activeSession.current = null;
    pendingConnection.current?.close(); pendingConnection.current = null; generation.current++;
    setSession(null); setCredential(''); setAgents([]); setSources([]); setAccess(null); setSelection(null); setNode(null);
    setSearch(''); setOwner(''); setEnvironment(''); setOptions({ owners: [], environments: [] }); setTruncated(false);
    setBusy(false); setConnecting(false); setTab('inventory');
  }, []);
  const invalidateAuthentication = useCallback(() => {
    authenticationGeneration.current++; authenticationRequest.current?.abort();
    clearWorkspace(); setAuthentication({ mode: 'unavailable' });
    setError('Your company session ended or its access changed. Check sign-in to continue.');
  }, [clearWorkspace]);
  const reportError = useCallback(error => {
    if (error?.code === 'VIEWER_SESSION_ENDED') return;
    if (auth.current.mode === 'oidc' && [401, 403].includes(error?.status)) { invalidateAuthentication(); return; }
    setError(errorMessage(error));
  }, [invalidateAuthentication]);
  const openWorkspace = useCallback(async next => {
    pendingConnection.current?.close(); pendingConnection.current = next; setConnecting(true);
    try {
      const [listing, health] = await Promise.all([next.query('list_agents', { limit: 100 }), next.query('get_inventory_health', {})]);
      if (pendingConnection.current !== next) return;
      setAgents(listing.data.agents ?? []); setOptions(agentOptions(listing.data.agents ?? [])); setTruncated(Boolean(listing.data.truncated));
      setSources(health.data.sources ?? []); setCredential(''); activeSession.current = next; setSession(next);
    } catch (error) { next.close(); if (pendingConnection.current === next) reportError(error); }
    finally { if (pendingConnection.current === next) { pendingConnection.current = null; setConnecting(false); } }
  }, [reportError]);
  const companyWorkspace = useCallback(value => ({ ...createCompanyQuerySession(value.csrfToken, { onEnded: invalidateAuthentication }),
    demo: false, company: true, csrfToken: value.csrfToken }), [invalidateAuthentication]);
  const bootstrap = useCallback(async ({ connect = true, message = '' } = {}) => {
    const run = ++authenticationGeneration.current;
    authenticationRequest.current?.abort(); const controller = new AbortController(); authenticationRequest.current = controller;
    clearWorkspace(); setAuthentication({ mode: 'pending' }); setConnecting(true); setError(message);
    try {
      const value = await readCompanySession({ signal: controller.signal });
      if (run !== authenticationGeneration.current || controller.signal.aborted) return;
      setAuthentication(value); auth.current = value;
      if (value.mode === 'oidc' && value.authenticated && connect && document.visibilityState !== 'hidden') await openWorkspace(companyWorkspace(value));
      return value;
    } catch (error) {
      if (run !== authenticationGeneration.current || controller.signal.aborted) return;
      setAuthentication({ mode: 'unavailable' });
      setError('Sign-in settings could not be checked. Retry to connect, or open the local synthetic demo.');
    } finally { if (run === authenticationGeneration.current) { authenticationRequest.current = null; setConnecting(false); } }
  }, [clearWorkspace, companyWorkspace, openWorkspace]);
  useEffect(() => {
    let message = '';
    if (window.location.pathname === '/' && window.location.search === '?auth_error=1') {
      message = 'Company sign-in could not be completed. Try again.'; window.history.replaceState(null, '', '/');
    }
    void bootstrap({ message });
    return () => { authenticationGeneration.current++; authenticationRequest.current?.abort(); activeSession.current?.close(); pendingConnection.current?.close(); };
  }, [bootstrap]);
  useEffect(() => {
    if (authentication.mode !== 'oidc' || !authentication.authenticated || session?.demo) return;
    return watchCompanySession({ expiresAt: authentication.expiresAt,
      onInvalidate: () => clearWorkspace(), onRevalidate: reason => { void bootstrap({ message: reason === 'expired' ? 'Your company session expired. Sign in again.' : '' }); } });
  }, [authentication, session?.demo, clearWorkspace, bootstrap]);
  async function connect(event, demo = false) {
    event?.preventDefault(); setError('');
    if (!demo && auth.current.mode !== 'bearer') return;
    authenticationGeneration.current++; authenticationRequest.current?.abort(); authenticationRequest.current = null;
    const token = credential.trim();
    if (demo && auth.current.mode !== 'bearer') setAuthentication({ mode: logoutToken.current ? 'logout-unconfirmed' : 'unavailable' });
    await openWorkspace({ ...createQuerySession(demo ? queryDemo : (operation, args, options) => queryReference(token, operation, args, options)), demo, company: false });
  }
  async function signIn() {
    let value = auth.current;
    if (value.mode !== 'oidc') return;
    if (Date.parse(value.expiresAt) <= Date.now()) value = await bootstrap({ connect: false });
    if (value?.mode !== 'oidc') return;
    setConnecting(true); setError('');
    if (value.authenticated) { await openWorkspace(companyWorkspace(value)); return; }
    const run = ++authenticationGeneration.current, controller = new AbortController();
    authenticationRequest.current?.abort(); authenticationRequest.current = controller;
    try {
      const destination = await startCompanyLogin(value.csrfToken, { signal: controller.signal });
      if (run !== authenticationGeneration.current || controller.signal.aborted) return;
      window.location.assign(destination);
    } catch (error) { if (run === authenticationGeneration.current && !controller.signal.aborted) {
      setAuthentication({ mode: 'unavailable' }); setError('Company sign-in could not be started. Check sign-in and try again.');
    } } finally { if (run === authenticationGeneration.current) { authenticationRequest.current = null; setConnecting(false); } }
  }
  async function logout() {
    const retry = !activeSession.current?.company && Boolean(logoutToken.current);
    const token = activeSession.current?.company ? activeSession.current.csrfToken : logoutToken.current;
    const run = ++authenticationGeneration.current;
    authenticationRequest.current?.abort(); authenticationRequest.current = null;
    clearWorkspace(); setError('');
    if (!token) return;
    const controller = new AbortController(); authenticationRequest.current = controller;
    logoutToken.current = token; setAuthentication({ mode: 'signing-out' }); setConnecting(true);
    try {
      if (retry) {
        const value = await retryCompanyLogout({ signal: controller.signal });
        if (run !== authenticationGeneration.current || controller.signal.aborted) return;
        logoutToken.current = null; auth.current = value; setAuthentication(value); return;
      }
      await endCompanySession(token, { signal: controller.signal });
      if (run !== authenticationGeneration.current || controller.signal.aborted) return;
      logoutToken.current = null; await bootstrap({ connect: false });
    } catch {
      if (run !== authenticationGeneration.current || controller.signal.aborted) return;
      setAuthentication({ mode: 'logout-unconfirmed' });
      setError('Local evidence was cleared, but server sign-out could not be confirmed. Retry sign-out before reconnecting.');
    } finally { if (run === authenticationGeneration.current) { authenticationRequest.current = null; setConnecting(false); } }
  }
  useEffect(() => {
    if (!session) return;
    let active = true;
    const timer = setTimeout(() => {
      query('list_agents', { ...(search ? { search } : {}), ...(owner ? { ownerId: owner } : {}), ...(environment ? { environment } : {}), limit: 100 })
        .then(result => { if (active) { setAgents(result.data.agents ?? []); setTruncated(Boolean(result.data.truncated)); } })
        .catch(error => { if (active) reportError(error); });
    }, 200);
    return () => { active = false; clearTimeout(timer); };
  }, [session, search, owner, environment, query, reportError]);
  async function selectAgent(agent) {
    const request = ++generation.current;
    setTab('inventory'); setSelection(agent); setAccess(null); setNode(null); setBusy(true); setError('');
    try { const result = await query('get_agent_access', { sourceId: agent.sourceId, agentId: agent.id ?? agent.agentId });
      if (request === generation.current) { setAccess(result); setNode(result.graph?.nodes.find(item => item.label === 'GuardAgent') ?? null); }
    } catch (error) { if (request === generation.current) reportError(error); } finally { if (request === generation.current) setBusy(false); }
  }
  async function refresh() { const stamp = generation.current; setError(''); try { const result = await query('get_inventory_health', {}); if (stamp !== generation.current) return; setSources(result.data.sources ?? []); if (selection) await selectAgent(selection); } catch (error) { if (stamp === generation.current) reportError(error); } }
  const tabs = [['inventory', 'Agent inventory', 'network'], ['resources', 'Potential access', 'search'], ['changes', 'Changes', 'clock'], ['health', 'Health', 'shield']];
  return <div className="app"><header className="topbar"><a className="brand" href="/" onClick={event => { event.preventDefault(); setTab('inventory'); }}><span className="brand-mark"><Icon name="network" size={22}/></span><span>Agent Guard <b> / </b><strong>Map</strong></span></a><div className="topbar-right"><span className="reference-label">REFERENCE WORKSPACE</span>{session && <><Status tone={session.demo ? 'amber' : 'green'}>{session.demo ? 'Synthetic demo' : session.company ? 'Company session' : 'Scoped connection'}</Status><button className="text-button" onClick={logout}><Icon name="logout" size={16}/>{session.company ? 'Sign out' : 'Disconnect'}</button></>}</div></header>
    {!session ? <main className="login-layout"><section className="login-intro"><span className="eyebrow">THE AGENT REFERENCE MAP</span><h1>Understand your agents.<br/><span>Follow the evidence.</span></h1><p>Explore agents, declared grants and their connected systems in one scoped view. See what is observed, what has changed and what remains unknown.</p><div className="intro-features"><div><Icon name="network"/><span>Focused relationships</span></div><div><Icon name="shield"/><span>Read-only reference</span></div><div><Icon name="clock"/><span>Independent capture times</span></div></div><div className="intro-diagram" aria-hidden="true"><span>Agent</span><i/><span>Task</span><i/><span>Declared grant</span><i/><span>Resource</span></div></section>
      <section className="login-card"><span className="login-icon"><Icon name="lock" size={24}/></span><h2>Connect to your inventory</h2>
        {authentication.mode === 'bearer' ? <><p>Use a reference credential issued by your host administrator. Your company and team scope is set by the service.</p><form onSubmit={connect}><label>Reference credential<input type="password" autoComplete="off" spellCheck={false} required value={credential} onChange={event => setCredential(event.target.value)} placeholder="agm_v1.…" maxLength={128}/></label><button className="primary-button full" disabled={connecting}>{connecting ? 'Connecting…' : 'Open agent map'}<Icon name="arrow"/></button></form><p className="credential-note">The credential stays in memory for this page. It is never saved in browser storage.</p></> :
          authentication.mode === 'oidc' ? <><p>Sign in with your company account. Your access to agents and teams is assigned by the host administrator.</p><button className="primary-button full" onClick={signIn} disabled={connecting}>{connecting ? 'Connecting…' : authentication.authenticated ? 'Open company map' : 'Sign in with company account'}<Icon name="arrow"/></button><p className="credential-note">Your sign-in credentials stay with your identity provider. This page receives a scoped browser session.</p></> :
          authentication.mode === 'pending' || authentication.mode === 'signing-out' ? <p role="status">{authentication.mode === 'pending' ? 'Checking sign-in settings…' : 'Signing out…'}</p> :
          <button className="primary-button full" onClick={() => authentication.mode === 'logout-unconfirmed' ? logout() : bootstrap()} disabled={connecting}>{authentication.mode === 'logout-unconfirmed' ? 'Retry sign out' : 'Check sign-in'}<Icon name="arrow"/></button>}
        {error && <Notice error>{error}</Notice>}<div className="demo-divider"><span>or explore the interface</span></div><button className="secondary-button full" onClick={event => connect(event, true)} disabled={authentication.mode === 'signing-out'}>Open synthetic demo</button><p className="demo-note">Demo data is local to this page and is not live inventory.</p></section></main> : <>
      {session.demo && <div className="demo-banner"><span className="demo-dot"/><strong>Demo workspace</strong><span>Synthetic evidence. No executor, cloud account or production service is connected.</span></div>}
      <nav className="nav-tabs" aria-label="Reference views">{tabs.map(([id, title, icon]) => <button key={id} className={tab === id ? 'active' : ''} onClick={() => { setTab(id); setError(''); }} aria-current={tab === id ? 'page' : undefined}><Icon name={icon} size={17}/>{title}</button>)}<button className="refresh-button" onClick={refresh}><Icon name="refresh" size={16}/>Refresh evidence</button></nav>
      <main className="workspace"><div className="page-heading"><div><span className="eyebrow">YOUR AUTHORIZED INVENTORY</span><h1>{tab === 'inventory' ? 'Agent inventory' : tab === 'resources' ? 'Trace potential access' : tab === 'changes' ? 'What changed' : 'Collection health'}</h1><p>{tab === 'inventory' ? 'Start with an agent. Explore the relationships that support its declared access.' : 'Scope and evidence stay attached to every result.'}</p></div><div className="summary-metrics"><div><strong>{agents.length}{truncated ? '+' : ''}</strong><span>Visible agents</span></div><div><strong>{sources.length}</strong><span>Visible sources</span></div><div><strong className="metric-mode">Read only</strong><span>Reference mode</span></div></div></div>
        {error && <div className="page-error"><Notice error>{error}</Notice><button className="icon-button" aria-label="Dismiss error" onClick={() => setError('')}><Icon name="close" size={16}/></button></div>}
        {tab === 'inventory' ? <div className="inventory-layout"><aside className="agent-sidebar"><div className="sidebar-title"><h2>Agents</h2><span className="count">{agents.length}</span></div><div className="search-field"><Icon name="search" size={17}/><input aria-label="Search visible agents" placeholder="Search agents…" value={search} onChange={event => setSearch(event.target.value)} maxLength={256}/></div><div className="filter-row"><select aria-label="Filter by owner" value={owner} onChange={event => setOwner(event.target.value)}><option value="">All owners</option>{options.owners.map(value => <option key={value}>{value}</option>)}</select><select aria-label="Filter by environment" value={environment} onChange={event => setEnvironment(event.target.value)}><option value="">All environments</option>{options.environments.map(value => <option key={value}>{value}</option>)}</select></div>
          <div className="agent-list">{agents.length ? agents.map(agent => <button className={`agent-card ${selection?.id === agent.id ? 'selected' : ''}`} key={`${agent.sourceId}-${agent.id}`} onClick={() => selectAgent(agent)}><span className="agent-avatar"><Icon name="network" size={19}/></span><span className="agent-card-copy"><strong>{agent.name ?? agent.agentId}</strong><small>{agent.teamId ?? 'No team'}<span>·</span>{agent.environments?.[0] ?? 'Environment unknown'}</small><span className="agent-owner">{agent.ownerId ?? 'Owner not assigned'}</span></span><Icon name="arrow" size={14}/></button>) : <p className="sidebar-empty">No agents match these visible filters.</p>}</div>{truncated && <p className="fine-print">Narrow your search to see the remaining visible results.</p>}<div className="sidebar-footer"><Icon name="lock" size={14}/><span>Filtered by server-side access rules</span></div></aside>
          <div className="agent-content">{busy ? <div className="loading" role="status"><span className="spinner"/>Loading scoped evidence…</div> : access ? <><div className="selected-heading"><div><span className="eyebrow">{access.data.agent.teamId ?? 'AGENT DETAIL'}</span><h2>{access.data.agent.name ?? access.data.agent.agentId}</h2><p>{access.data.agent.ownerId ?? 'Owner unknown'}<span>·</span>{access.data.agent.environments?.join(', ') || 'Environment unknown'}</p></div><Status tone="amber">Execution assessment unknown</Status></div><div className="graph-evidence"><Graph graph={access.graph ?? { nodes: [], edges: [] }} policyEvidence={access.data.policyEvidence} onSelect={selectNode}/><Evidence node={node} graph={access.graph} select={selectNode}/></div><div className="access-summary"><span><b>{access.data.tasks?.length ?? 0}</b> visible tasks</span><span><b>{access.data.grants?.length ?? 0}</b> declared grants</span><span><b>{access.data.connections?.length ?? 0}</b> MCP connections</span><span>Captured {displayTime(access.data.receipt?.generatedAt ?? access.observedAt)}</span></div><PolicyEvidence evidence={access.data.policyEvidence} graph={access.graph}/><Explain access={access.data} graph={access.graph} query={query} reportError={reportError}/></> : <div className="welcome-card"><Empty title="Choose an agent to explore">Select an agent from your visible inventory to inspect its tasks, declared grants, MCP connections and cloud associations.</Empty><div className="welcome-principles"><div><span>01</span><h3>Follow relationships</h3><p>Start with one focused neighborhood.</p></div><div><span>02</span><h3>Inspect the evidence</h3><p>Keep declared and observed state distinct.</p></div><div><span>03</span><h3>Keep unknowns visible</h3><p>A map does not authorize execution.</p></div></div></div>}</div></div> : tab === 'resources' ? <ResourceLookup query={query} onAgent={selectAgent} reportError={reportError}/> : tab === 'changes' ? <Changes sources={sources} query={query} reportError={reportError}/> : <Health sources={sources}/>}
      </main><footer className="app-footer"><span>Agent Guard · Evidence reference</span><span>Declared access is not an execution decision.</span></footer></>}
  </div>;
}
createRoot(document.getElementById('root')).render(<App/>);
