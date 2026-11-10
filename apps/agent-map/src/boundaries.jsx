import React from 'react';
import { displayTime, nodeName } from './view-model.mjs';
import { boundaryFlagRows, FLAG_BADGES, flagBadge, outsideGuardRows } from './boundary-model.mjs';
import { DataTable } from './inventory.jsx';

/** Colour always comes with its text label; absent (or unrequested) flags render nothing. */
export function FlagBadge({ value }) {
  const badge = flagBadge(value);
  return badge ? <span className={`flag-badge ${badge.tone}`}><span className="status-dot"/>{badge.label}</span> : null;
}
export function FlagLegend() {
  return <p className="flag-legend"><span>Dangerous three:</span>{Object.values(FLAG_BADGES).map(badge => <FlagBadge key={badge.status} value={badge.status}/>)}<span>No badge: a leg is known absent.</span></p>;
}
const full = value => <span className="full-reference">{value ?? 'Unknown'}</span>;
/** An evidence entity ID, with its visible name and a link to the graph node when the focused graph has it. */
function Entity({ id, graph, onNode }) {
  if (!id) return null;
  const node = graph?.nodes?.find(item => item.entityId === id || item.id === id);
  return <>{node ? <strong>{nodeName(node)}</strong> : null}{full(id)}{node && onNode && <button type="button" className="text-link" onClick={() => onNode(node)}>Show in graph</button>}</>;
}
function EvidenceList({ items, graph, onNode, empty }) {
  if (!items.length) return <span className="subtle">{empty}</span>;
  return <ul className="flag-evidence">{items.map((item, index) => <li key={index}><span>{item.reasonLabel}</span>
    {item.taskId && <span>Task <Entity id={item.taskId} graph={graph} onNode={onNode}/></span>}
    {item.tool && <span>Tool {full(item.tool)}</span>}
    {item.resourceBindingId && <span>Resource binding <Entity id={item.resourceBindingId} graph={graph} onNode={onNode}/></span>}</li>)}</ul>;
}

export function BoundaryFlags({ flags, graph, onNode }) {
  const flag = boundaryFlagRows(flags);
  if (!flag) return <section className="inventory-card" aria-label="Boundary flags"><h3>Boundary flags</h3><p className="subtle">This service did not report boundary flags for the agent. The flag remains unknown.</p></section>;
  return <section className="inventory-card boundary-flags" aria-label="Boundary flags"><div className="section-heading"><div><h3>Boundary flags</h3><p className="subtle">Dangerous three: one live task that can read private data, read outside content and send data out. Declared grants and labels only.</p></div>{flag.badge ? <FlagBadge value={flag.status}/> : <span className="pill">{flag.statusLabel}</span>}</div>
    <DataTable title="Dangerous three legs" rows={flag.legs} columns={[
      ['Leg', x => <strong>{x.label}</strong>], ['State', x => <span className={`leg-state ${x.state}`}>{x.stateLabel}</span>],
      ['Evidence', x => <EvidenceList items={x.evidence} graph={graph} onNode={onNode} empty={x.state === 'unknown' ? 'No declaration establishes this leg either way.' : 'No supporting evidence listed.'}/>],
    ]}/>
    {flag.mitigation.length > 0 && <><h4>Mitigation</h4><EvidenceList items={flag.mitigation} graph={graph} onNode={onNode} empty=""/></>}
    {flag.evidenceTruncated && <p className="notice" role="note">More evidence exists than is listed here: up to eight items are shown per leg.</p>}
    <dl className="inventory-properties"><div><dt>Live tasks evaluated</dt><dd>{flag.liveTasks ?? 'Unknown'}</dd></div><div><dt>Evidence</dt><dd>Declared</dd></div></dl>
    {flag.notes.length > 0 && <><h4>Notes</h4><ul>{flag.notes.map(note => <li key={note}>{note}</li>)}</ul></>}
    {flag.limitations.length > 0 && <><h4>Limitations</h4><ul className="fine-print">{flag.limitations.map(item => <li key={item}>{item}</li>)}</ul></>}
  </section>;
}

export function OutsideGuard({ outsideGuard, graph, onNode }) {
  const rows = outsideGuardRows(outsideGuard);
  const direct = rows.directAccess.flatMap(deployment => deployment.entries.length
    ? deployment.entries.map(entry => ({ ...entry, deployment }))
    : [{ id: deployment.id, deployment, empty: true }]);
  return <section className="inventory-card outside-guard" aria-label="Outside the guard"><div className="section-heading"><div><h3>Outside the guard</h3><p className="subtle">Access the guard does not check: paths the host declares, and buckets a guarded tool’s cloud identity reaches beyond its grants.</p></div><span className="pill">Declared and candidate evidence</span></div>
    {!outsideGuard && <p className="subtle">This service did not report outside-guard evidence. It remains unknown.</p>}
    <DataTable title="Declared direct paths" rows={direct} columns={[
      ['Deployment', x => <><strong>{x.deployment.deploymentId}</strong><br/><span className={`direct-status ${x.deployment.status}`}>{x.deployment.statusLabel}</span></>],
      ['Kind', x => x.empty ? 'None listed' : x.kind], ['Description', x => x.empty ? '—' : (x.description ?? 'Unknown')],
      ['Target reference', x => x.empty ? '—' : x.targetRef ? full(x.targetRef) : x.targetWithheld ? 'A resource outside your scope (not shown)' : 'Not declared'],
      ['Path', x => x.empty ? '—' : <Entity id={x.id} graph={graph} onNode={onNode}/>],
    ]} empty="No deployment in this neighborhood reported direct-path status."/>
    <DataTable title="Tool identity scope" rows={rows.identityScope} columns={[
      ['Tool', x => full(x.tool)], ['Execution binding', x => <Entity id={x.executionBindingId} graph={graph} onNode={onNode}/>],
      ['Identity', x => x.identityId ? <Entity id={x.identityId} graph={graph} onNode={onNode}/> : 'No static identity resolved'],
      ['Status', x => <><span className={`scope-status ${x.status}`}>{x.statusLabel}</span>{x.reason && <><br/><small>{x.reason.replaceAll('_', ' ')}</small></>}</>],
      ['Buckets beyond grants', x => <>{x.extraResources.length ? <ul className="flag-evidence">{x.extraResources.map(extra => <li key={`${extra.resourceId}:${extra.relationship}`}><strong>{extra.bucketName}</strong><span>{extra.relationshipLabel}</span><span>{extra.hasCondition ? <>Condition unresolved: {extra.conditionKeys.map(key => <code key={key}>{key}</code>)}</> : 'No condition on candidate'}</span></li>)}</ul> : 'None listed'}{x.withheld && <p><small>Further buckets are not mapped by any binding in your scope (another team's, or none at all) and are not listed.</small></p>}</>],
      ['Truncated', x => x.truncated ? 'Yes: more buckets than shown' : 'No'], ['Observed', x => displayTime(x.observedAt)],
    ]} empty="No execution binding in this neighborhood."/>
    <p className="notice">Only S3 identity policies and host declarations are checked. Bucket policies, SCPs and permission boundaries are not, so buckets are candidates. “None declared” is the host’s claim, not a check, and no status here rules access out.</p>
  </section>;
}
