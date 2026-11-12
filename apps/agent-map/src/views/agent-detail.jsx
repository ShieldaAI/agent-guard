import React, { useCallback, useEffect, useRef, useState } from 'react';
import { displayTime, errorCode, errorMessage, graphTooLarge, kindName, policyNotEvaluated } from '../view-model.mjs';
import { ownershipLabel } from '../inventory-model.mjs';
import { codeText, displayValue, fieldText, label } from '../labels.mjs';
import { Note, Notice } from '../components/common.jsx';
import { Identifier } from '../components/identifier.jsx';
import {
  DataTable,
  MissingStreams,
  Pager,
  Pending,
  Properties,
  relationshipColumns,
  usePage,
} from '../components/tables.jsx';
import { PolicySection } from '../policy-evidence.jsx';
import { BoundaryFlags, OutsideGuard } from '../boundaries.jsx';
import { Evidence, Graph } from './graph.jsx';
import { AgentExplanation } from './explain.jsx';
import { ChangesView } from './changes.jsx';

const id = value => <Identifier value={value} />;

/** Columns of each paged section of `get_agent_inventory`, in the service's own field names. */
const sectionColumns = {
  deployments: [
    ['Deployment', x => id(x.deploymentId)],
    ['Environment', x => displayValue(x.environment)],
    [
      'Runtime / build',
      x => (
        <>
          {id(x.runtimeRef)}
          <br />
          {id(x.buildRef)}
        </>
      ),
    ],
    ['Generation', x => displayValue(x.workloadGeneration)],
    ['Binding authority', x => id(x.bindingAuthority)],
  ],
  tasks: [
    ['Task', x => id(x.taskId)],
    ['Principal', x => id(x.principalId)],
    ['Revocation at capture', x => fieldText('revoked', x.revoked)],
    ['Deadline', x => displayTime(x.budget?.deadline)],
    ['Calls / limit', x => `${displayValue(x.usage?.calls)} / ${displayValue(x.budget?.maxCalls)}`],
  ],
  permissions: [
    ['Task', x => id(x.taskId)],
    ['Declared tool', x => id(x.tool)],
    ['Declared resource selectors', x => id(x.resources)],
    ['Evidence', () => 'Declared grant · current access unknown'],
  ],
  tools: [
    ['Tool', x => id(x.name)],
    ['Revision', x => displayValue(x.revision)],
    ['Registration', x => fieldText('registered', x.registered)],
    ['Metadata approved', x => fieldText('approved', x.approved)],
    ['Action approval required', x => fieldText('requires_approval', x.requires_approval)],
  ],
  resources: [
    ['Resource', x => displayValue(x.displayName ?? x.bindingId)],
    ['Exact selector', x => id(x.resourceRef)],
    ['Scope', x => label('matchScope', x.scope)],
    ['Owner', ownershipLabel],
    ['Sensitivity', x => label('sensitivity', x.sensitivity)],
    ['Declared actions', x => displayValue(x.actions)],
  ],
  connections: [
    ['Connection', x => id(x.connection_id ?? x.id)],
    ['State at capture', x => label('connectionState', x.state)],
    ['Metadata', x => label('metadataState', x.metadata_state)],
    ['Observed', x => displayTime(x.observed_at)],
  ],
  credentials: [
    ['Reference name', x => displayValue(x.name)],
    ['Opaque reference', x => id(x.credentialId)],
    ['Lifecycle at capture', x => label('lifecycle', x.lifecycleState)],
    ['Rotation at capture', x => label('rotation', x.rotationStatus)],
    ['Expiry at capture', x => displayTime(x.expiresAt)],
    [
      'Intended issuer / audiences / recipients',
      x => (
        <>
          {id(x.issuerRef)}
          <br />
          {id(x.audienceRefs)}
          <br />
          {id(x.recipientRefs)}
        </>
      ),
    ],
  ],
  bindings: [
    ['Binding', x => id(x.binding_id ?? x.id)],
    ['Binding type', x => kindName(x.kind)],
    ['Tool', x => id(x.tool)],
    [
      'Identity selection',
      x => (x.kind === 'GuardResourceBinding' ? 'Not applicable' : label('identitySelection', x.identity_selection)),
    ],
    ['Evidence', x => label('evidenceKind', x.evidence_kind)],
    ['Authority', x => id(x.authority_id)],
  ],
  identities: [
    ['Identity', x => id(x.arn ?? x.id)],
    ['Provider', x => label('provider', x.provider)],
    ['Collection state', x => label('cloudStatus', x.cloud_status)],
    ['Evidence', () => 'Observed identity · access unknown'],
  ],
  relationships: relationshipColumns,
};

function AgentSection({ title, section, agent, query, reportError, onResource, onData }) {
  const page = usePage(
    query,
    'get_agent_inventory',
    { sourceId: agent.sourceId, agentId: agent.id ?? agent.agentId, section },
    reportError,
  );
  // The first page also feeds the explanation form, so it is not requested a second time.
  useEffect(() => {
    if (!onData) return;
    if (page.status === 'error') onData([]);
    else if (page.status === 'ready' && !(page.data.offset > 0)) onData(page.data.items ?? []);
  }, [page.status, page.data, onData]);
  const columns =
    section === 'resources' && onResource
      ? [
          [
            'Resource',
            x => (
              <button className="text-link" onClick={() => onResource(x)}>
                {x.displayName ?? x.bindingId}
              </button>
            ),
          ],
          ...sectionColumns.resources.slice(1),
        ]
      : sectionColumns[section];
  return (
    <section className="inventory-card">
      <h3>{title}</h3>
      {page.status !== 'ready' ? (
        <Pending page={page} label={title.toLowerCase()} />
      ) : section === 'policies' ? (
        <PolicySection data={page.data} onPage={page.onPage} label={title.toLowerCase()} />
      ) : (
        <>
          <DataTable title={title} rows={page.data.items ?? []} columns={columns} />
          <Pager
            data={page.data}
            count={page.data.items?.length ?? 0}
            onPage={page.onPage}
            label={title.toLowerCase()}
          />
        </>
      )}
    </section>
  );
}

function Provenance({ agent, receipt }) {
  return (
    <Properties
      items={[
        ['Host assertion authority', id(agent.authorityId)],
        ['Ownership source', codeText(agent.ownershipSource)],
        ['Host manifest', id(agent.manifestId)],
        ['Manifest revision', displayValue(agent.manifestRevision)],
        ['Ownership observed', displayTime(agent.ownershipObservedAt)],
        ['Snapshot captured', displayTime(receipt?.generatedAt)],
        ['Source', id(agent.sourceId)],
        ['Snapshot', id(receipt?.snapshotId)],
      ]}
    />
  );
}

const GRAPH_LIMIT = 'This neighborhood exceeds the graph display limit. All paged inventory sections remain available.';
/**
 * One `get_agent_access` read per selected agent. It feeds the two security sections that
 * lead the overview and the optional graph below them, so they always agree.
 */
function useAgentAccess(agent, query, reportError) {
  const [state, setState] = useState({ status: 'loading', result: null, error: '', limited: false }),
    [attempt, setAttempt] = useState(0);
  useEffect(() => {
    let active = true;
    const controller = new AbortController();
    setState({ status: 'loading', result: null, error: '', limited: false });
    query(
      'get_agent_access',
      { sourceId: agent.sourceId, agentId: agent.id ?? agent.agentId },
      { signal: controller.signal },
    )
      .then(next => {
        if (!active) return;
        // A graph past the display cap is left out by the service; the boundary evidence still arrives.
        if (!graphTooLarge(next) && (!Array.isArray(next.graph?.nodes) || !Array.isArray(next.graph?.edges)))
          throw Object.assign(new Error('VIEWER_RESPONSE_INVALID'), { code: 'VIEWER_RESPONSE_INVALID' });
        setState({ status: 'ready', result: next, error: '', limited: false });
      })
      .catch(error => {
        if (!active) return;
        const limited = errorCode(error).includes('LIMIT') || error?.status === 413;
        setState({ status: 'error', result: null, error: limited ? GRAPH_LIMIT : errorMessage(error), limited });
        // The failure is shown in the sections it affects, with a retry.
        reportError(error, { shown: true });
      });
    return () => {
      active = false;
      controller.abort();
    };
  }, [agent, query, reportError, attempt]);
  return { ...state, large: graphTooLarge(state.result), retry: () => setAttempt(value => value + 1) };
}

/** Boundary flags and outside-guard evidence: the two sections that lead the agent overview. */
function BoundarySections({ access, onNode }) {
  if (access.status === 'loading')
    return (
      <section className="inventory-card">
        <h3>Boundary flags and outside-guard evidence</h3>
        <p role="status">Loading boundary evidence…</p>
      </section>
    );
  if (access.status === 'error')
    return (
      <section className="inventory-card">
        <h3>Boundary flags and outside-guard evidence</h3>
        <Notice>
          {access.limited
            ? 'Boundary flags and outside-guard evidence are not shown because this neighborhood exceeds the display limit. The paged inventory sections remain available.'
            : `Boundary flags and outside-guard evidence could not be loaded. They remain unknown. ${access.error}`}
        </Notice>
        {!access.limited && (
          <button className="secondary-button" onClick={access.retry}>
            Retry boundary evidence
          </button>
        )}
      </section>
    );
  const { data, graph } = access.result;
  return (
    <>
      <BoundaryFlags flags={data.boundaryFlags} graph={graph} onNode={onNode} />
      <OutsideGuard outsideGuard={data.outsideGuard} graph={graph} onNode={onNode} />
    </>
  );
}

/** The optional picture of the same read. Every identifier and relationship is also in the paged tables. */
function RelationshipGraph({ access, shown, onToggle, node, onSelect, cardRef }) {
  const { status, result, large, error } = access,
    data = result?.data;
  return (
    <section className="inventory-card" ref={cardRef}>
      <h3>Relationship graph</h3>
      <p className="subtle">
        {large
          ? 'This neighborhood is too large to draw. Its boundary flags and outside-guard evidence are shown above, and the full identifiers and relationships remain available in paged tables.'
          : 'Optional focused visualization. The full identifiers and relationships remain available in paged tables.'}
      </p>
      <button className="secondary-button" disabled={status === 'loading'} onClick={onToggle}>
        {status === 'loading' ? 'Loading graph…' : shown ? 'Hide graph' : 'Show graph'}
      </button>
      {shown && (error || large) && <Notice>{large ? GRAPH_LIMIT : error}</Notice>}
      {shown && result && !large && (
        <>
          {policyNotEvaluated(data.policyCoverage) && (
            <Notice>
              Policy candidates are not drawn: this agent has more task and binding pairs than one read evaluates.
              Access remains unknown.
            </Notice>
          )}
          <div className="graph-evidence">
            <Graph
              graph={result.graph}
              policyEvidence={data.policyEvidence}
              outsideGuard={data.outsideGuard}
              flagStatus={data.boundaryFlags?.find(flag => flag?.kind === 'dangerous_three')?.status ?? null}
              tenantId={data.receipt?.tenantId ?? null}
              selected={node}
              onSelect={onSelect}
            />
            <Evidence node={node} graph={result.graph} select={onSelect} />
          </div>
        </>
      )}
    </section>
  );
}

const TABS = [
  ['overview', 'Overview'],
  ['permissions', 'Permissions'],
  ['connections', 'Connections & resources'],
  ['changes', 'Agent changes'],
];
const CONNECTION_SECTIONS = [
  ['Connected resources', 'resources'],
  ['MCP connections', 'connections'],
  ['Tool and resource bindings', 'bindings'],
  ['Observed identities', 'identities'],
  ['Credential references', 'credentials'],
  ['Relationships', 'relationships'],
];

/**
 * One selected agent: its heading, then four tabs. The overview leads with the two security
 * sections. `focusHeading` is a ref the caller sets when the user has just chosen this agent,
 * so focus (and the scroll position) moves to the agent's name.
 */
export function AgentDetail({ response, query, reportError, onAgent, onResource, focusHeading }) {
  const data = response.data,
    agent = data.agent,
    [tab, setTab] = useState('overview'),
    [explained, setExplained] = useState(false),
    [grants, setGrants] = useState(null),
    [graphShown, setGraphShown] = useState(false),
    [node, setNode] = useState(null);
  const heading = useRef(null),
    graphCard = useRef(null);
  const access = useAgentAccess(agent, query, reportError);
  // Keep the grants first loaded: paging the permissions table must not reset the explanation form.
  const keepGrants = useCallback(items => setGrants(value => (value?.length ? value : items)), []);
  useEffect(() => {
    if (!focusHeading?.current) return;
    focusHeading.current = false;
    heading.current?.focus({ preventScroll: true });
    heading.current?.scrollIntoView({ block: 'nearest' });
  }, [focusHeading]);
  // A new read starts at the agent's own node; a graph that is not drawn has no selection.
  useEffect(() => {
    const result = access.result;
    setNode(result?.graph ? (result.graph.nodes.find(item => item.label === 'GuardAgent') ?? null) : null);
  }, [access.result]);
  const select = useCallback(value => setNode(value), []);
  const showNode = useCallback(value => {
    setNode(value);
    setGraphShown(true);
    // Wait for the graph to render before bringing it into view.
    setTimeout(() => graphCard.current?.scrollIntoView({ block: 'start' }), 0);
  }, []);
  return (
    <>
      <div className="selected-heading">
        <div>
          <span className="eyebrow">{agent.teamId ?? 'TEAM UNKNOWN'}</span>
          <h2 ref={heading} tabIndex={-1}>
            {agent.name ?? agent.agentId}
          </h2>
          <p>
            {ownershipLabel(agent)}
            <span>·</span>
            {agent.environments?.join(', ') || 'Environment unknown'}
          </p>
        </div>
        <span className="status amber">Current execution requires a live check</span>
      </div>
      <nav className="agent-detail-tabs" aria-label="Selected agent views">
        {TABS.map(([name, title]) => (
          <button
            type="button"
            key={name}
            aria-current={tab === name ? 'page' : undefined}
            onClick={() => setTab(name)}
          >
            {title}
          </button>
        ))}
      </nav>
      {tab === 'overview' && (
        <>
          <BoundarySections access={access} onNode={showNode} />
          <section className="inventory-card">
            <h3>Agent overview</h3>
            <Properties
              items={[
                ['Purpose', displayValue(agent.purpose)],
                ['Lifecycle at capture', label('lifecycle', agent.lifecycleState)],
                ['Ownership status', ownershipLabel(agent)],
                ['Reported owner reference', id(agent.ownerId)],
                ['Agent identity', id(agent.agentId)],
                ['Team', displayValue(agent.teamId)],
              ]}
            />
            <Provenance agent={agent} receipt={data.receipt} />
            {!agent.authorityId && (
              <Note>
                Legacy metadata does not establish ownership or lifecycle state. Missing fields remain unknown.
              </Note>
            )}
          </section>
          <AgentSection
            title="Deployments"
            section="deployments"
            agent={agent}
            query={query}
            reportError={reportError}
          />
          <AgentSection title="Tasks" section="tasks" agent={agent} query={query} reportError={reportError} />
          <RelationshipGraph
            access={access}
            shown={graphShown}
            onToggle={() => setGraphShown(value => !value)}
            node={node}
            onSelect={select}
            cardRef={graphCard}
          />
        </>
      )}
      {tab === 'permissions' && (
        <>
          <MissingStreams />
          <AgentSection
            title="Declared permissions"
            section="permissions"
            agent={agent}
            query={query}
            reportError={reportError}
            onData={keepGrants}
          />
          <AgentSection title="Tools" section="tools" agent={agent} query={query} reportError={reportError} />
          {!explained && (
            <AgentSection
              title="Mapped policy candidates"
              section="policies"
              agent={agent}
              query={query}
              reportError={reportError}
            />
          )}{' '}
          <AgentExplanation
            agent={agent}
            grants={grants}
            query={query}
            reportError={reportError}
            onExplained={setExplained}
          />
        </>
      )}
      {tab === 'connections' && (
        <>
          <Note>
            These relationships are host observations. Opaque credential references contain no credentials and cannot be
            used to authenticate.
          </Note>
          {CONNECTION_SECTIONS.map(([title, section]) => (
            <AgentSection
              key={section}
              title={title}
              section={section}
              agent={agent}
              query={query}
              reportError={reportError}
              onResource={onResource}
            />
          ))}
        </>
      )}
      {tab === 'changes' && (
        <ChangesView
          sourceId={agent.sourceId}
          agentId={agent.id ?? agent.agentId}
          query={query}
          reportError={reportError}
          onAgent={onAgent}
        />
      )}
    </>
  );
}
