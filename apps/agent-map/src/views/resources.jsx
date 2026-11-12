import React, { useEffect, useRef, useState } from 'react';
import { displayTime, errorMessage, policyNotEvaluated } from '../view-model.mjs';
import { KNOWN_ACTIONS, ownershipLabel, resourceReferences } from '../inventory-model.mjs';
import { outsideGuardLabel, reachNotEvaluated, relationshipName, unknownReasonLabel } from '../boundary-model.mjs';
import { LABELS, codeText, displayValue, label } from '../labels.mjs';
import { Empty, Icon, Note, Notice, Status } from '../components/common.jsx';
import { Identifier } from '../components/identifier.jsx';
import { AgentLinks, DataTable, Pager, Pending, Properties, useDebounced, usePage } from '../components/tables.jsx';
import { PolicyEvidence } from '../policy-evidence.jsx';

const id = value => <Identifier value={value} />;
/** Reverse outside-guard view: declared direct paths and tool identities that reach this resource without a binding. */
function ResourceOutsideGuard({ value }) {
  const direct = Array.isArray(value.directAccess) ? value.directAccess : [],
    identities = Array.isArray(value.identities) ? value.identities : [],
    reasons = Array.isArray(value.unknownReasons) ? value.unknownReasons : [];
  return (
    <section className="outside-guard-resource" aria-label="Reachable outside the guard">
      <h3>Reachable outside the guard</h3>
      <p>
        <span
          className={`reach-label ${value.status === 'yes' ? 'yes' : value.status === 'none_found' ? 'none' : 'unknown'}`}
        >
          {outsideGuardLabel(value.status)}
        </span>{' '}
        <span className="pill">Declared and candidate evidence</span>
      </p>
      {reachNotEvaluated(value) ? (
        <p className="notice" role="note">
          Reach was not judged in this read, so no paths or identities are listed. This does not mean none exist.
        </p>
      ) : (
        <>
          <DataTable
            title="Declared direct paths to this resource"
            rows={direct}
            columns={[
              ['Kind', x => label('directAccessKind', x.kind)],
              ['Description', x => displayValue(x.description)],
              ['Deployment', x => id(x.deploymentId)],
              ['Access reference', x => id(x.accessId)],
              ['Evidence', () => 'Declared by host'],
            ]}
            empty="No declared direct path targets this resource."
          />
          <DataTable
            title="Tool identities that reach this resource without a binding"
            rows={identities}
            columns={[
              ['Tool', x => id(x.tool)],
              ['Identity', x => id(x.identityId)],
              ['Execution binding', x => id(x.executionBindingId)],
              ['Relationship', x => relationshipName(x.relationship)],
              [
                'Condition',
                x =>
                  x.hasCondition ? (
                    <>
                      Condition unresolved
                      <br />
                      {id(x.conditionKeys)}
                    </>
                  ) : (
                    'No condition on candidate'
                  ),
              ],
            ]}
            empty="No tool identity candidate reaches this resource outside its bindings."
          />
        </>
      )}
      {(value.directAccessTruncated === true || value.identitiesTruncated === true) && (
        <p className="notice" role="note">
          More entries reach this resource than are listed: each table shows the first 100.
        </p>
      )}
      {reasons.length > 0 && (
        <>
          <h4>Why parts remain unknown</h4>
          <ul>
            {reasons.map(reason => (
              <li key={reason}>{unknownReasonLabel(reason)}</li>
            ))}
          </ul>
        </>
      )}
      <Note>
        Only S3 identity policies and host declarations are checked. A none-found result is not a check of the host and
        does not mean the resource is unreachable.
      </Note>
    </section>
  );
}

function ResourceDetail({ resource, query, reportError, onAgent, onBack }) {
  const page = usePage(
    query,
    'get_resource_access',
    { sourceId: resource.sourceId, resourceId: resource.id },
    reportError,
  );
  const row = page.data?.resource ?? resource;
  return (
    <section className="wide-card">
      <button className="text-link" onClick={onBack}>
        Back to resources
      </button>
      <h2>{row.displayName ?? row.bindingId}</h2>
      <Note>Connected agents are declared relationship evidence, not a current permission decision.</Note>
      <Properties
        items={[
          ['Resource reference', id(row.resourceRef)],
          ['Boundary', label('matchScope', row.scope)],
          ['Declared actions', displayValue(row.actions)],
          ['Ownership status', ownershipLabel(row)],
          ['Reported owner reference', id(row.ownerId)],
          ['Ownership source', codeText(row.ownershipSource)],
          ['Sensitivity', label('sensitivity', row.sensitivity)],
          ['Approved destination references', id(row.approvedDestinations)],
          ['Host authority', id(row.authorityId)],
          ['Observed', displayTime(row.observedAt)],
        ]}
      />
      <DataTable
        title="Resource targets"
        rows={row.targets ?? []}
        columns={[
          ['Name / reference', x => id(x.name ?? x.arn ?? x.host_resource_id)],
          ['Provider', x => label('provider', x.provider)],
          ['Kind', x => label('kind', x.kind)],
        ]}
      />
      <DataTable
        title="Dependencies"
        rows={row.dependencies ?? []}
        columns={[
          ['Resource', x => displayValue(x.displayName ?? x.bindingId)],
          ['Full reference', x => id(x.id)],
        ]}
      />
      {page.status === 'ready' && page.data.outsideGuard && <ResourceOutsideGuard value={page.data.outsideGuard} />}
      <h3>Connected visible agents</h3>
      {page.status !== 'ready' ? (
        <Pending page={page} label="resource relationships" />
      ) : (
        <>
          <AgentLinks agents={page.data.agents ?? []} onAgent={onAgent} />
          <Pager data={page.data} count={page.data.agents?.length ?? 0} onPage={page.onPage} label="connected agents" />
        </>
      )}
    </section>
  );
}

/** Which agents hold a declared grant mapped to one resource reference and cloud action. */
export function ResourceLookup({ query, onAgent, reportError, references = [] }) {
  const [resourceRef, setResource] = useState(''),
    [action, setAction] = useState(KNOWN_ACTIONS[0]),
    [result, setResult] = useState(null),
    [error, setError] = useState(''),
    [busy, setBusy] = useState(false);
  const request = useRef(null);
  useEffect(() => () => request.current?.abort(), []);
  function change(set, value) {
    setResult(null);
    setError('');
    set(value);
  }
  async function submit(event) {
    event.preventDefault();
    setBusy(true);
    setResult(null);
    setError('');
    const controller = new AbortController();
    request.current = controller;
    try {
      const response = await query('find_agents_with_access', { resourceRef, action }, { signal: controller.signal });
      if (!controller.signal.aborted) setResult(response.data);
    } catch (failure) {
      if (!controller.signal.aborted) {
        // Shown beside the form that caused it.
        setError(errorMessage(failure));
        reportError(failure, { shown: true });
      }
    } finally {
      if (!controller.signal.aborted) setBusy(false);
    }
  }
  const candidates = result?.candidates ?? [];
  return (
    <section className="wide-card">
      <div className="section-heading">
        <div>
          <h2>Find potential access</h2>
          <p>Match an exact resource reference and declared cloud action in your visible inventory.</p>
        </div>
        <Icon name="search" size={24} />
      </div>
      <form className="resource-form" onSubmit={submit}>
        <label>
          Resource reference
          <input
            list="lookup-resource-options"
            value={resourceRef}
            disabled={busy}
            onChange={event => change(setResource, event.target.value)}
            required
            maxLength={4096}
            placeholder="Choose or type a reference or ARN"
          />
          <datalist id="lookup-resource-options">
            {references.map(reference => (
              <option key={reference} value={reference} />
            ))}
          </datalist>
        </label>
        <label>
          Action
          <input
            list="lookup-action-options"
            value={action}
            disabled={busy}
            onChange={event => change(setAction, event.target.value)}
            required
            maxLength={256}
            placeholder="s3:GetObject"
          />
          <datalist id="lookup-action-options">
            {KNOWN_ACTIONS.map(name => (
              <option key={name} value={name} />
            ))}
          </datalist>
        </label>
        <button className="primary-button" disabled={busy}>
          {busy ? 'Searching…' : 'Find candidates'}
          <Icon name="arrow" size={16} />
        </button>
      </form>
      {error && <Note error>{error}</Note>}
      {result?.truncated && (
        <Notice>
          More agents matched than this search can display
          {result.truncatedReason ? ` (${label('truncatedReason', result.truncatedReason)})` : ''}. The list below is
          incomplete.
        </Notice>
      )}
      <Notice>
        Results describe potential access through declared grants and explicit mappings. They do not establish effective
        cloud permission.
      </Notice>
      {result ? (
        candidates.length ? (
          <div className="candidate-list">
            {candidates.map((candidate, index) => {
              const agent = candidate.agent ?? {},
                evidence = Array.isArray(candidate.evidence) ? candidate.evidence : [];
              return (
                <article className="candidate-result" key={`${agent.sourceId}:${agent.id}:${index}`}>
                  <button className="candidate" onClick={() => onAgent(agent)}>
                    <div className="agent-avatar">
                      <Icon name="network" />
                    </div>
                    <div>
                      <h3>{agent.name ?? agent.agentId ?? 'Candidate agent'}</h3>
                      <p>{agent.teamId ?? 'Unassigned team'}</p>
                    </div>
                    <Status tone="amber">Potential access</Status>
                    <Icon name="arrow" />
                  </button>
                  <PolicyEvidence
                    compact
                    notEvaluated={evidence.some(item => policyNotEvaluated(item.policyCoverage))}
                    evidence={evidence.flatMap(item => item.policyEvidence ?? [])}
                  />
                </article>
              );
            })}
          </div>
        ) : (
          <Empty title="No matching candidates">
            No visible mapping matched this reference and action. This does not prove access is denied.
          </Empty>
        )
      ) : (
        <Empty title="Start with a resource">
          Use an exact reference from a host binding or from an agent’s evidence panel.
        </Empty>
      )}
    </section>
  );
}

/** The resource index, one resource's detail, and the "potential access" lookup. */
export function ResourcesBrowse({ query, reportError, onAgent, ownerFilter, initialResource }) {
  const [search, setSearch] = useState(''),
    [sensitivity, setSensitivity] = useState(''),
    [selected, setSelected] = useState(initialResource ?? null),
    [mode, setMode] = useState('browse'),
    [references, setReferences] = useState([]),
    term = useDebounced(search);
  const page = usePage(
    query,
    'list_resources',
    {
      ...(ownerFilter ? { ownerId: ownerFilter.ownerId, sourceId: ownerFilter.sourceId } : {}),
      ...(term ? { search: term } : {}),
      ...(sensitivity ? { sensitivity } : {}),
    },
    reportError,
    !selected && mode === 'browse',
  );
  // The lookup offers the references of the resources already listed here.
  useEffect(() => {
    if (page.status === 'ready') setReferences(resourceReferences(page.data.resources));
  }, [page.status, page.data]);
  if (selected)
    return (
      <ResourceDetail
        key={`${selected.sourceId}:${selected.id}`}
        resource={selected}
        query={query}
        reportError={reportError}
        onAgent={onAgent}
        onBack={() => setSelected(null)}
      />
    );
  return (
    <>
      <nav className="agent-detail-tabs" aria-label="Resource views">
        <button aria-current={mode === 'browse' ? 'page' : undefined} onClick={() => setMode('browse')}>
          Browse resources
        </button>
        <button aria-current={mode === 'lookup' ? 'page' : undefined} onClick={() => setMode('lookup')}>
          Potential access
        </button>
      </nav>
      {mode === 'lookup' ? (
        <ResourceLookup query={query} onAgent={onAgent} reportError={reportError} references={references} />
      ) : (
        <section className="wide-card">
          <h2>Host-bound resources</h2>
          <p className="subtle">
            Exact host bindings, ownership and dependencies. Unbound declared selectors appear in agent Permissions, not
            this resource index. Shared provider resources retain their original scope.
          </p>
          {ownerFilter && (
            <Note>
              Filtered to owner {ownerFilter.name} in source <Identifier value={ownerFilter.sourceId} />. Select
              Resources again to clear this filter.
            </Note>
          )}
          <div className="inventory-filters">
            <label>
              Search resources
              <input value={search} onChange={event => setSearch(event.target.value)} maxLength={256} />
            </label>
            <label>
              Sensitivity
              <select value={sensitivity} onChange={event => setSensitivity(event.target.value)}>
                <option value="">All sensitivity labels</option>
                {Object.entries(LABELS.sensitivity).map(([value, title]) => (
                  <option key={value} value={value}>
                    {title}
                  </option>
                ))}
              </select>
            </label>
          </div>
          {page.status !== 'ready' ? (
            <Pending page={page} label="resources" />
          ) : (
            <>
              <DataTable
                title="Visible resources"
                rows={page.data.resources ?? []}
                columns={[
                  [
                    'Resource',
                    x => (
                      <button className="text-link" onClick={() => setSelected(x)}>
                        {x.displayName ?? x.bindingId}
                      </button>
                    ),
                  ],
                  ['Owner', ownershipLabel],
                  ['Boundary', x => label('matchScope', x.scope)],
                  ['Sensitivity', x => label('sensitivity', x.sensitivity)],
                  ['Selector', x => id(x.resourceRef)],
                  ['Reachable outside guard', x => outsideGuardLabel(x.outsideGuard)],
                ]}
              />
              <Pager data={page.data} count={page.data.resources?.length ?? 0} onPage={page.onPage} label="resources" />
            </>
          )}
        </section>
      )}
    </>
  );
}
