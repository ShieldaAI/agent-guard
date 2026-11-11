import React, { useState } from 'react';
import { displayTime } from './view-model.mjs';
import { shownValue, sourceOptionLabel } from './inventory-model.mjs';
import { DataTable, Note, Pager, Pending, Properties, usePage } from './inventory.jsx';
import { accountReasonLabel, discoveryHidden, taskLineageLabel, unclaimedSummary, undeclaredActivityLabel } from './discovery-model.mjs';

const ref = value => <span className="full-reference">{shownValue(value)}</span>;
function Hidden({ data }) { return <Note>{typeof data.note === 'string' ? data.note : 'Shown only to readers with all-teams visibility.'}</Note>; }

/** Tasks and callers that ran through an enrolled executor and belong to no declared agent. */
function UndeclaredActivity({ sources, query, reportError }) {
  const [sourceId, setSource] = useState(sources[0]?.id ?? ''), [kind, setKind] = useState('tasks');
  const page = usePage(query, 'list_undeclared_activity', { sourceId, kind }, reportError, Boolean(sourceId));
  const selected = sources.find(source => source.id === sourceId), data = page.data;
  return <section className="wide-card"><h2>Activity nobody declared</h2><p className="subtle">Tasks and callers that ran through an enrolled executor and belong to no declared agent. A lead to follow up: declare the agent in the manifest, or add the missing task binding. An agent that does not use the guard leaves nothing here.</p>
    <div className="inventory-filters"><label>Authorized source<select value={sourceId} onChange={event => setSource(event.target.value)}><option value="">Select source</option>{sources.map((source, index) => <option key={source.id} value={source.id}>{sourceOptionLabel(source, index)}</option>)}</select></label><label>Show<select value={kind} onChange={event => setKind(event.target.value)}><option value="tasks">Tasks</option><option value="principals">Callers</option></select></label></div>
    {selected && <p role="status"><span className="pill">Observed, not assessed</span> {undeclaredActivityLabel(selected.undeclaredActivity).text}</p>}
    {!sourceId ? <p className="subtle">Choose a source to list its undeclared activity.</p> : page.status !== 'ready' ? <Pending page={page} label="undeclared activity"/> : discoveryHidden(data) ? <Hidden data={data}/> : <>
      {kind === 'tasks' ? <DataTable title="Tasks with no declared agent" rows={data.items ?? []} columns={[
        ['Task', x => ref(x.taskId)], ['Caller', x => ref(x.principalId)], ['Relation to declared agents', taskLineageLabel], ['Tools with a declared grant', x => <>{ref(x.tools)}{x.toolsTruncated === true && <small> (first 32)</small>}</>], ['Revocation at capture', x => x.revoked === true ? 'Revoked' : x.revoked === false ? 'Not revoked' : 'Unknown'],
      ]} empty="No task without a declared agent in this captured snapshot."/> : <DataTable title="Callers with no declared agent" rows={data.items ?? []} columns={[
        ['Caller', x => ref(x.principalId)], ['Tasks at capture', x => `${shownValue(x.tasks)}${x.tasksCapped === true ? '+' : ''}`], ['Evidence', () => 'Observed caller · agent unknown'],
      ]} empty="No caller without a declared agent in this captured snapshot."/>}
      <Pager data={data} count={data.items?.length ?? 0} onPage={page.onPage} label="undeclared activity"/>
      {data.totalIsMinimum === true && <Note>Counting stopped at {data.total}; there are at least that many.</Note>}
      <Properties items={[['Snapshot captured', displayTime(data.receipt?.generatedAt)], ['Tasks captured', displayTime(data.receipt?.coverage?.tasks?.observedAt)]]}/>
    </>}
  </section>;
}

/** IAM roles and users of the enrolled AWS accounts that no declared agent names: candidates only. */
function UnclaimedIdentities({ query, reportError }) {
  const page = usePage(query, 'list_unclaimed_identities', {}, reportError);
  const data = page.data, summary = data ? unclaimedSummary(data) : null;
  return <section className="wide-card"><h2>Unclaimed cloud identities</h2><p className="subtle">IAM roles and users in your enrolled AWS accounts that no declared agent's execution binding names. Candidates to review, not findings: most roles are not agents.</p>
    {page.status !== 'ready' ? <Pending page={page} label="cloud identities"/> : discoveryHidden(data) ? <Hidden data={data}/> : <>
      <p role="status"><span className="pill">Candidates, not findings</span> {summary.text}</p>
      <DataTable title="AWS accounts" rows={(data.accounts ?? []).map(account => ({ ...account, id: `${account.tenantId}:${account.partition}:${account.accountId}` }))} columns={[
        ['Account', x => ref(x.accountId)], ['Tenant', x => ref(x.tenantId)], ['Collection', accountReasonLabel], ['Collected', x => displayTime(x.observedAt)], ['Roles and users', x => x.status === 'complete' ? shownValue(x.observed) : 'Unknown'], ['Unclaimed', x => x.status === 'complete' ? shownValue(x.unclaimed) : 'Unknown'],
      ]} empty="No AWS account is collected for your tenants, so nothing can be listed. This is not a statement that no such identity exists."/>
      {data.status !== 'unknown' && <><DataTable title="Unclaimed IAM identities" rows={(data.identities ?? []).map(identity => ({ ...identity, id: identity.arn }))} columns={[
        ['Identity', x => <><strong>{shownValue(x.name)}</strong><br/>{ref(x.arn)}</>], ['Kind', x => x.kind === 'role' ? 'IAM role' : x.kind === 'user' ? 'IAM user' : 'Unknown'], ['Path', x => ref(x.path)], ['Account', x => ref(x.accountId)], ['Evidence', () => 'Candidate · use unknown'],
      ]} empty="No unclaimed identity in the accounts that could be judged."/><Pager data={data} count={data.identities?.length ?? 0} onPage={page.onPage} label="cloud identities"/></>}
      {data.bindingsWithoutIdentity === true && <Note>Some declared execution bindings name no identity. A listed identity may be the one such a binding uses.</Note>}
      <Note>An identity is claimed only when a declared binding names its exact ARN. Role assumption, instance profiles and federation are not followed, and only enrolled AWS accounts are collected.</Note>
    </>}
  </section>;
}

export function DiscoveryView({ sources, query, reportError }) {
  return <><Note>Discovery views help you find agents the manifest does not list. They are read-only leads: nothing here creates an agent, and nothing grants or blocks access.</Note><UndeclaredActivity sources={sources} query={query} reportError={reportError}/><UnclaimedIdentities query={query} reportError={reportError}/></>;
}
