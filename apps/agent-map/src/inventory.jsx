import React, { useEffect, useId, useState } from 'react';
import { displayTime, errorMessage, kindName } from './view-model.mjs';
import { ownershipLabel, pageInfo, relationshipLabel, shownValue, sourceOptionLabel } from './inventory-model.mjs';
import { PolicyEvidence } from './policy-evidence.jsx';

function Note({ children, error = false }) { return <p className={`notice ${error ? 'error' : ''}`} role={error ? 'alert' : undefined}>{children}</p>; }
const text = value => shownValue(value);
const ref = value => <span className="full-reference">{text(value)}</span>;
function Endpoint({ name, label, id }) { return <><strong>{name ?? kindName(label)}</strong>{label && <small className="reference-kind">{kindName(label)}</small>}<details className="reference-details"><summary>Full identifier</summary>{ref(id)}</details></>; }
export function Pager({ data, count, onPage, label = 'results', busy = false }) {
  const page = pageInfo(data, count);
  return <div className="inventory-pagination" aria-label={`${label} pages`}><span aria-live="polite">{page.label}</span>
    <button type="button" disabled={busy || page.previous === null} aria-label={`Previous ${label} page`} onClick={() => onPage(page.previous)}>Previous</button>
    <button type="button" disabled={busy || page.next === null} aria-label={`Next ${label} page`} onClick={() => onPage(page.next)}>Next</button>
    {page.incomplete && <span className="fine-print">Incomplete results. Narrow the filters.</span>}</div>;
}
function usePage(query, operation, args, reportError, enabled = true) {
  const key = JSON.stringify(args), [page, setPage] = useState({ key, offset: 0 }), [attempt, setAttempt] = useState(0), [result, setResult] = useState(null);
  const offset = page.key === key ? page.offset : 0;
  const requestKey = `${key}:${offset}:${attempt}`;
  useEffect(() => {
    if (!enabled) return;
    let active = true;
    const controller = new AbortController();
    setResult({ key: requestKey, status: 'loading' });
    query(operation, { ...JSON.parse(key), offset, limit: 20 }, { signal: controller.signal }).then(response => {
      if (active) setResult({ key: requestKey, status: 'ready', data: response.data });
    }).catch(error => { if (active) { setResult({ key: requestKey, status: 'error', message: errorMessage(error) }); reportError(error); } });
    return () => { active = false; controller.abort(); };
  }, [query, operation, key, offset, attempt, enabled, reportError]);
  const current = enabled && result?.key === requestKey ? result : null;
  return { data: current?.data, status: current?.status ?? (enabled ? 'loading' : 'idle'), message: current?.message,
    onPage: value => setPage({ key, offset: value }), retry: () => setAttempt(value => value + 1) };
}
function Pending({ page, label }) {
  return page.status === 'error' ? <div><Note error>{page.message}</Note><button type="button" className="secondary-button" onClick={page.retry}>Retry {label}</button></div>
    : <p role="status">Loading {label}…</p>;
}
function DataTable({ title, rows, columns, empty = 'No visible records in this captured section.' }) {
  const hintId = useId();
  if (!rows.length) return <p className="subtle">{empty}</p>;
  return <><p id={hintId} className="table-scroll-hint">Scroll horizontally for more columns. Keyboard users can focus the table and use arrow keys.</p><div className="evidence-table-scroll" tabIndex="0" role="region" aria-label={`${title} table`} aria-describedby={hintId}><table className="evidence-table"><caption>{title}</caption><thead><tr>{columns.map(([name]) => <th scope="col" key={name}>{name}</th>)}</tr></thead>
    <tbody>{rows.map((item, index) => <tr key={`${item.id ?? item.entityId ?? index}:${index}`}>{columns.map(([name, read]) => <td key={name}>{read(item)}</td>)}</tr>)}</tbody></table></div></>;
}
function Properties({ items }) { return <dl className="inventory-properties">{items.map(([name, value]) => <div key={name}><dt>{name}</dt><dd>{value}</dd></div>)}</dl>; }
function Provenance({ agent, receipt }) { return <Properties items={[
  ['Host assertion authority', ref(agent.authorityId)], ['Ownership source', text(agent.ownershipSource)],
  ['Host manifest', ref(agent.manifestId)], ['Manifest revision', text(agent.manifestRevision)],
  ['Ownership observed', displayTime(agent.ownershipObservedAt)], ['Snapshot captured', displayTime(receipt?.generatedAt)],
  ['Source', ref(agent.sourceId)], ['Snapshot', ref(receipt?.snapshotId)],
]} />; }
function MissingStreams() { return <Note>Approval events, request-time decisions, backend receipts and external policy history are not collected. A declared grant or mapped policy candidate does not establish current execution permission.</Note>; }

const sectionColumns = {
  deployments: [['Deployment', x => ref(x.deploymentId)], ['Environment', x => text(x.environment)], ['Runtime / build', x => <>{ref(x.runtimeRef)}<br/>{ref(x.buildRef)}</>], ['Generation', x => text(x.workloadGeneration)], ['Binding authority', x => ref(x.bindingAuthority)]],
  tasks: [['Task', x => ref(x.taskId)], ['Principal', x => ref(x.principalId)], ['Revocation at capture', x => x.revoked === true ? 'Revoked' : x.revoked === false ? 'Not revoked' : 'Unknown'], ['Deadline', x => displayTime(x.budget?.deadline)], ['Calls / limit', x => `${text(x.usage?.calls)} / ${text(x.budget?.maxCalls)}`]],
  permissions: [['Task', x => ref(x.taskId)], ['Declared tool', x => ref(x.tool)], ['Declared resource selectors', x => ref(x.resources)], ['Evidence', () => 'Declared grant · current access unknown']],
  tools: [['Tool', x => ref(x.name)], ['Revision', x => text(x.version ?? x.revision ?? x.implementation_version)], ['Registration', x => text(x.registered)], ['Metadata approved', x => text(x.approved)], ['Action approval required', x => text(x.requires_approval)]],
  resources: [['Resource', x => text(x.displayName ?? x.bindingId)], ['Exact selector', x => ref(x.resourceRef)], ['Scope', x => text(x.scope)], ['Owner', ownershipLabel], ['Sensitivity', x => text(x.sensitivity)], ['Declared actions', x => text(x.actions)]],
  connections: [['Connection', x => ref(x.connection_id ?? x.connectionId ?? x.id)], ['State at capture', x => text(x.state)], ['Metadata', x => text(x.metadata_state)], ['Metadata revision', x => text(x.metadata_revision)], ['Observed', x => displayTime(x.observed_at ?? x.captured_at)]],
  credentials: [['Reference name', x => text(x.name)], ['Opaque reference', x => ref(x.credentialId)], ['Lifecycle at capture', x => text(x.lifecycleState)], ['Rotation at capture', x => text(x.rotationStatus)], ['Expiry at capture', x => displayTime(x.expiresAt)], ['Intended issuer / audiences / recipients', x => <>{ref(x.issuerRef)}<br/>{ref(x.audienceRefs)}<br/>{ref(x.recipientRefs)}</>]],
  bindings: [['Binding', x => ref(x.binding_id ?? x.id)], ['Binding type', x => kindName(x.kind)], ['Tool', x => ref(x.tool)], ['Identity selection', x => x.kind === 'GuardResourceBinding' ? 'Not applicable' : text(x.identity_selection)], ['Evidence', x => text(x.evidence_kind)], ['Authority', x => ref(x.authority_id)]],
  identities: [['Identity', x => ref(x.arn ?? x.principal_id ?? x.id)], ['Provider', x => text(x.provider)], ['Collection state', x => text(x.cloud_status)], ['Evidence', () => 'Observed identity · access unknown']],
  relationships: [['From', x => <Endpoint name={x.sourceName} label={x.sourceLabel} id={x.source}/>], ['Relationship', x => relationshipLabel(x.kind)], ['To', x => <Endpoint name={x.targetName} label={x.targetLabel} id={x.target}/>]],
};
function AgentSection({ title, section, agent, query, reportError, onResource }) {
  const page = usePage(query, 'get_agent_inventory', { sourceId: agent.sourceId, agentId: agent.id ?? agent.agentId, section }, reportError);
  const columns = section === 'resources' && onResource ? [['Resource', x => <button className="text-link" onClick={() => onResource(x)}>{x.displayName ?? x.bindingId}</button>], ...sectionColumns.resources.slice(1)] : sectionColumns[section];
  return <section className="inventory-card"><h3>{title}</h3>{page.status !== 'ready' ? <Pending page={page} label={title.toLowerCase()}/> : <>{section === 'policies' ? <PolicyEvidence evidence={page.data.items ?? []}/> : <DataTable title={title} rows={page.data.items ?? []} columns={columns}/>}<Pager data={page.data} count={page.data.items?.length ?? 0} onPage={page.onPage} label={title.toLowerCase()}/></>}</section>;
}
export function AgentInventory({ response, query, reportError, graphView, explanation, onAgent, onResource }) {
  const data = response.data, agent = data.agent, [tab, setTab] = useState('overview'), [explained, setExplained] = useState(false);
  const tabs = [['overview', 'Overview'], ['permissions', 'Permissions'], ['connections', 'Connections & resources'], ['changes', 'Agent changes']];
  return <><div className="selected-heading"><div><span className="eyebrow">{agent.teamId ?? 'TEAM UNKNOWN'}</span><h2>{agent.name ?? agent.agentId}</h2><p>{ownershipLabel(agent)}<span>·</span>{agent.environments?.join(', ') || 'Environment unknown'}</p></div><span className="status amber">Current execution requires a live check</span></div>
    <nav className="agent-detail-tabs" aria-label="Selected agent views">{tabs.map(([id, title]) => <button type="button" key={id} aria-current={tab === id ? 'page' : undefined} onClick={() => setTab(id)}>{title}</button>)}</nav>
    {tab === 'overview' && <><section className="inventory-card"><h3>Agent overview</h3><Properties items={[
      ['Purpose', text(agent.purpose)], ['Lifecycle at capture', text(agent.lifecycleState)], ['Ownership status', ownershipLabel(agent)], ['Reported owner reference', ref(agent.ownerId)],
      ['Agent identity', ref(agent.agentId)], ['Team', text(agent.teamId)],
    ]}/><Provenance agent={agent} receipt={data.receipt}/>{!agent.authorityId && <Note>Legacy metadata does not establish ownership or lifecycle state. Missing fields remain unknown.</Note>}</section>
      <AgentSection title="Deployments" section="deployments" agent={agent} query={query} reportError={reportError}/><AgentSection title="Tasks" section="tasks" agent={agent} query={query} reportError={reportError}/>{graphView}</>}
    {tab === 'permissions' && <><MissingStreams/><AgentSection title="Declared permissions" section="permissions" agent={agent} query={query} reportError={reportError}/><AgentSection title="Tools" section="tools" agent={agent} query={query} reportError={reportError}/>{!explained && <AgentSection title="Mapped policy candidates" section="policies" agent={agent} query={query} reportError={reportError}/>} {explanation(setExplained)}</>}
    {tab === 'connections' && <><Note>These relationships are host observations. Opaque credential references contain no credentials and cannot be used to authenticate.</Note>
      {[['Connected resources', 'resources'], ['MCP connections', 'connections'], ['Tool and resource bindings', 'bindings'], ['Observed identities', 'identities'], ['Credential references', 'credentials'], ['Relationships', 'relationships']].map(([title, section]) => <AgentSection key={section} title={title} section={section} agent={agent} query={query} reportError={reportError} onResource={onResource}/>)}</>}
    {tab === 'changes' && <ChangesView sourceId={agent.sourceId} agentId={agent.id ?? agent.agentId} query={query} reportError={reportError} onAgent={onAgent}/>}
  </>;
}

export function OwnersBrowse({ query, reportError, onOwner, onOwnerResources }) {
  const [search, setSearch] = useState(''), [kind, setKind] = useState('');
  const page = usePage(query, 'list_owners', { ...(search ? { search } : {}), ...(kind ? { kind } : {}) }, reportError);
  return <section className="wide-card"><h2>Owners and teams</h2><p className="subtle">Accountability asserted by enrolled hosts. Counts include only your visible relationships.</p><div className="inventory-filters"><label>Search owners<input value={search} onChange={e => setSearch(e.target.value)} maxLength={256}/></label><label>Owner kind<select value={kind} onChange={e => setKind(e.target.value)}><option value="">All kinds</option>{['person', 'team', 'service'].map(v => <option key={v}>{v}</option>)}</select></label></div>
    {page.status !== 'ready' ? <Pending page={page} label="owners"/> : <><DataTable title="Visible owners" rows={page.data.owners ?? []} columns={[
      ['Owner', x => <><strong>{x.name}</strong><br/>{ref(x.ownerId)}</>], ['Kind', x => text(x.kind)], ['Source', x => ref(x.sourceId)],
      ['Agents', x => <button className="text-link" onClick={() => onOwner(x)}>View {x.agentCount} agents</button>], ['Resources', x => <button className="text-link" onClick={() => onOwnerResources(x)}>View {x.resourceCount} resources</button>],
    ]} empty="No owner records are visible. Unassigned or uncollected ownership remains visible in the agent inventory."/><Pager data={page.data} count={page.data.owners?.length ?? 0} onPage={page.onPage} label="owners"/></>}
  </section>;
}
function ResourceDetail({ resource, query, reportError, onAgent, onBack }) {
  const page = usePage(query, 'get_resource_access', { sourceId: resource.sourceId, resourceId: resource.id }, reportError);
  const row = page.data?.resource ?? resource;
  return <section className="wide-card"><button className="text-link" onClick={onBack}>Back to resources</button><h2>{row.displayName ?? row.bindingId}</h2><Note>Connected agents are declared relationship evidence, not a current permission decision.</Note><Properties items={[
    ['Resource reference', ref(row.resourceRef)], ['Boundary', text(row.scope)], ['Declared actions', text(row.actions)], ['Ownership status', ownershipLabel(row)], ['Reported owner reference', ref(row.ownerId)], ['Ownership source', text(row.ownershipSource)], ['Sensitivity', text(row.sensitivity)], ['Approved destination references', ref(row.approvedDestinations)], ['Host authority', ref(row.authorityId)], ['Observed', displayTime(row.observedAt)],
  ]}/><DataTable title="Resource targets" rows={row.targets ?? []} columns={[
    ['Name / reference', x => ref(x.name ?? x.arn ?? x.host_resource_id)], ['Provider', x => text(x.provider)], ['Kind', x => text(x.kind)],
  ]}/><DataTable title="Dependencies" rows={row.dependencies ?? []} columns={[
    ['Resource', x => text(x.displayName ?? x.bindingId)], ['Full reference', x => ref(x.id)],
  ]}/><h3>Connected visible agents</h3>{page.status !== 'ready' ? <Pending page={page} label="resource relationships"/> : <><AgentLinks agents={page.data.agents ?? []} onAgent={onAgent}/><Pager data={page.data} count={page.data.agents?.length ?? 0} onPage={page.onPage} label="connected agents"/></>}</section>;
}
function AgentLinks({ agents, onAgent }) { return agents.length ? <ul className="agent-links">{agents.map(x => <li key={`${x.sourceId}:${x.id}`}><button className="text-link" onClick={() => onAgent(x)}>{x.name ?? x.agentId ?? x.id}</button></li>)}</ul> : <p className="subtle">No visible agent relationships were collected. This does not prove access is denied.</p>; }
export function ResourcesBrowse({ query, reportError, onAgent, ownerFilter, initialResource, lookup }) {
  const [search, setSearch] = useState(''), [sensitivity, setSensitivity] = useState(''), [selected, setSelected] = useState(initialResource ?? null), [mode, setMode] = useState('browse');
  const page = usePage(query, 'list_resources', { ...(ownerFilter ? { ownerId: ownerFilter.ownerId, sourceId: ownerFilter.sourceId } : {}), ...(search ? { search } : {}), ...(sensitivity ? { sensitivity } : {}) }, reportError, !selected && mode === 'browse');
  if (selected) return <ResourceDetail key={`${selected.sourceId}:${selected.id}`} resource={selected} query={query} reportError={reportError} onAgent={onAgent} onBack={() => setSelected(null)}/>;
  return <><nav className="agent-detail-tabs" aria-label="Resource views"><button aria-current={mode === 'browse' ? 'page' : undefined} onClick={() => setMode('browse')}>Browse resources</button><button aria-current={mode === 'lookup' ? 'page' : undefined} onClick={() => setMode('lookup')}>Potential access</button></nav>{mode === 'lookup' ? lookup : <section className="wide-card"><h2>Host-bound resources</h2><p className="subtle">Exact host bindings, ownership and dependencies. Unbound declared selectors appear in agent Permissions, not this resource index. Shared provider resources retain their original scope.</p>{ownerFilter && <Note>Filtered to owner {ownerFilter.name} in source {ownerFilter.sourceId}. Select Resources again to clear this filter.</Note>}
    <div className="inventory-filters"><label>Search resources<input value={search} onChange={e => setSearch(e.target.value)} maxLength={256}/></label><label>Sensitivity<select value={sensitivity} onChange={e => setSensitivity(e.target.value)}><option value="">All sensitivity labels</option>{['public', 'internal', 'confidential', 'restricted', 'unknown'].map(v => <option key={v}>{v}</option>)}</select></label></div>
    {page.status !== 'ready' ? <Pending page={page} label="resources"/> : <><DataTable title="Visible resources" rows={page.data.resources ?? []} columns={[
      ['Resource', x => <button className="text-link" onClick={() => setSelected(x)}>{x.displayName ?? x.bindingId}</button>], ['Owner', ownershipLabel], ['Boundary', x => text(x.scope)], ['Sensitivity', x => text(x.sensitivity)], ['Selector', x => ref(x.resourceRef)],
    ]}/><Pager data={page.data} count={page.data.resources?.length ?? 0} onPage={page.onPage} label="resources"/></>}
  </section>}</>;
}

export function ChangesView({ sources = [], sourceId: fixedSource, agentId, query, reportError, onAgent }) {
  const [sourceId, setSource] = useState(fixedSource ?? sources[0]?.id ?? ''), [kind, setKind] = useState('all'), [ready, setReady] = useState(false);
  const selectedSource = sources.find(source => source.id === sourceId);
  const page = usePage(query, 'get_changes', { sourceId, since: 'previous', ...(agentId ? { agentId } : {}), changeKind: kind }, reportError, ready && Boolean(sourceId));
  return <section className="wide-card"><h2>Snapshot comparison</h2><p className="subtle">Inspect exact changes between authorized retained snapshots. Changed declarations do not prove effective permission gain or loss.</p>
    <form className="inventory-filters" onSubmit={e => { e.preventDefault(); setReady(true); if (ready) page.retry(); }}>{!fixedSource && <label>Authorized source<select required value={sourceId} onChange={e => { setSource(e.target.value); setReady(false); }}><option value="">Select source</option>{sources.map((x, index) => <option key={x.id} value={x.id}>{sourceOptionLabel(x, index)}</option>)}</select></label>}<label>Change kind<select value={kind} onChange={e => { setKind(e.target.value); setReady(false); }}><option value="all">All changes</option><option value="permissions">Declared permissions</option><option value="ownership">Ownership</option><option value="bindings">Bindings and connections</option></select></label><button className="primary-button" disabled={!sourceId || page.status === 'loading'}>Compare snapshots</button></form>
    {selectedSource && <details className="reference-details"><summary>Selected source details</summary><Properties items={[
      ['Tenant', ref(selectedSource.tenantId)], ['Source reference', ref(selectedSource.sourceId ?? selectedSource.id)], ['Query source identifier', ref(selectedSource.id)],
    ]}/></details>}
    {page.status === 'idle' ? <p className="subtle">Choose a source and compare its retained snapshots.</p> : page.status !== 'ready' ? <Pending page={page} label="changes"/> : <>{page.data.coverageGap && <Note>The comparison baseline is unavailable. No complete change history can be inferred.</Note>}<Properties items={[
      ['Previous capture', displayTime(page.data.from?.generatedAt)], ['Current capture', displayTime(page.data.to?.generatedAt)],
    ]}/>{!(page.data.details ?? []).length ? <p className="subtle">{page.data.coverageGap ? 'Changes cannot be determined without a retained baseline.' : 'No matching changes in these visible retained snapshots.'}</p> : page.data.details.map((item, index) => <article className="change-detail" key={`${item.entityId}:${index}`}><h3>{item.name ?? item.entityId}</h3><p>{kindName(item.label)} · {item.kind} · {text(item.categories)}</p><DataTable title={`Before and after: ${item.name ?? item.entityId}`} rows={(item.changedFields ?? []).map(field => ({ id: field, field, before: item.before?.properties?.[field], after: item.after?.properties?.[field] }))} columns={[
      ['Field', x => x.field.replaceAll('_', ' ')], ['Before', x => item.before === null ? 'Not present in prior snapshot' : ref(x.before)], ['After', x => item.after === null ? 'Not present in current snapshot' : ref(x.after)],
    ]} empty="No displayed property change. Inspect the relationship changes below."/><h4>Affected visible agents</h4><AgentLinks agents={item.affectedAgents ?? []} onAgent={onAgent}/>{item.affectedAgentsTruncated && <Note>Showing {item.affectedAgents?.length ?? 0} of {item.affectedAgentsTotal} affected visible agents. Use the agent inventory to inspect the remaining agents.</Note>}</article>)}
    <Pager data={page.data} count={page.data.details?.length ?? 0} onPage={page.onPage} label="changes"/>
    {['added', 'removed'].map(type => <DataTable key={type} title={`${type === 'added' ? 'Added' : 'Removed'} relationships`} rows={page.data.relationships?.[type] ?? []} columns={sectionColumns.relationships} empty={`No ${type} relationships in this comparison page.`}/>)}<MissingStreams/><p className="fine-print">Net snapshot changes are not a complete intermediate event history.</p></>}
  </section>;
}
