import React, { useEffect, useMemo, useRef, useState } from 'react';
import cytoscape from 'cytoscape';
import { displayTime, errorMessage } from '../view-model.mjs';
import { sourceOptionLabel } from '../inventory-model.mjs';
import {
  HUB_KIND_NAME,
  LINK_GROUPS,
  changeCategoryName,
  directAccessText,
  egressText,
  isolationText,
  lastChangeText,
  linkRows,
  networkText,
  permissionsChanged,
  topologyElements,
  topologySummary,
} from '../topology-model.mjs';
import { FLAG_NAME } from '../boundary-model.mjs';
import { Icon, Note, Notice, Status } from '../components/common.jsx';
import { Identifier } from '../components/identifier.jsx';
import { DataTable, Properties } from '../components/tables.jsx';

const FLAG_TONE = Object.freeze({ exposed: 'danger', mitigated: 'amber', unknown: 'neutral' });
const STYLE = [
  {
    selector: 'node',
    style: {
      label: 'data(label)',
      'font-size': 11,
      'font-family': 'Inter, system-ui, sans-serif',
      color: '#314358',
      'text-valign': 'bottom',
      'text-margin-y': 6,
      'text-wrap': 'wrap',
      'text-max-width': 170,
      'text-background-color': '#f9fbfd',
      'text-background-opacity': 0.85,
      'text-background-padding': 2,
    },
  },
  {
    selector: 'node.agent',
    style: {
      'background-color': '#274b77',
      'border-color': '#183b65',
      'border-width': 2,
      width: 46,
      height: 46,
      color: '#173754',
      'font-weight': 600,
    },
  },
  { selector: 'node.flag-exposed', style: { 'border-color': '#b3261e', 'border-width': 5, color: '#8c1d18' } },
  { selector: 'node.flag-mitigated', style: { 'border-color': '#c48a1c', 'border-width': 5, color: '#6d4c10' } },
  { selector: 'node.flag-unknown', style: { 'border-color': '#7b8794', 'border-width': 5, 'border-style': 'dashed' } },
  {
    selector: 'node.changed',
    style: {
      'underlay-color': '#2b77be',
      'underlay-opacity': 0.18,
      'underlay-padding': 5,
      'underlay-shape': 'ellipse',
    },
  },
  { selector: 'node.hub', style: { width: 34, height: 34, 'border-width': 1.5, 'font-size': 10 } },
  {
    selector: 'node.hub-mcp_server',
    style: { 'background-color': '#e9e3f5', 'border-color': '#ab99c9', shape: 'hexagon' },
  },
  {
    selector: 'node.hub-cloud_identity, node.hub-principal, node.hub-credential',
    style: { 'background-color': '#f5ead7', 'border-color': '#c6a36c', shape: 'diamond', width: 38, height: 38 },
  },
  {
    selector: 'node.hub-network_segment',
    style: { 'background-color': '#e3f1f4', 'border-color': '#4f8fa0', shape: 'barrel', width: 40 },
  },
  {
    selector: 'node.hub-resource',
    style: { 'background-color': '#e1ede6', 'border-color': '#86ab96', shape: 'round-rectangle' },
  },
  { selector: 'node.sensitive', style: { 'border-color': '#b3261e', 'border-width': 2.5 } },
  {
    selector: 'node.box',
    style: {
      shape: 'round-rectangle',
      'background-color': '#f4f7fa',
      'background-opacity': 0.55,
      'border-width': 1.2,
      'border-color': '#9fb1c4',
      padding: 22,
      'text-valign': 'top',
      'text-halign': 'center',
      'text-margin-y': -4,
      'font-size': 10,
      'font-weight': 600,
      color: '#3d5166',
      'text-background-opacity': 0,
      'text-max-width': 400,
    },
  },
  {
    selector: 'node.box-environment',
    style: { 'background-color': '#eaf1f8', 'border-style': 'dashed', 'border-color': '#7f9bb8' },
  },
  { selector: 'node:selected', style: { 'border-width': 4, 'border-color': '#2b77be', 'overlay-opacity': 0 } },
  {
    selector: 'edge',
    style: {
      width: 1.3,
      'line-color': '#c3cfdb',
      'curve-style': 'bezier',
      label: 'data(label)',
      'font-size': 9,
      color: '#5a6a7c',
      'text-rotation': 'autorotate',
      'text-background-color': '#f9fbfd',
      'text-background-opacity': 0.9,
      'text-background-padding': 2,
    },
  },
  { selector: 'edge.hub-link', style: { 'line-style': 'dashed', label: '' } },
  {
    selector: 'edge.agent-link',
    style: {
      width: 2.6,
      'line-color': '#6b4fbb',
      'target-arrow-color': '#6b4fbb',
      color: '#4b3592',
      // Agents in one row would hide a straight link behind the agent between them.
      'curve-style': 'unbundled-bezier',
      'control-point-distances': -60,
      'control-point-weights': 0.5,
    },
  },
  { selector: 'edge.directed', style: { 'target-arrow-shape': 'triangle', 'arrow-scale': 0.9 } },
  { selector: 'edge:selected', style: { 'line-color': '#2b77be', 'target-arrow-color': '#2b77be', width: 3 } },
];

function TopologyGraph({ data, groups, labels, sourceNames, selected, onSelect }) {
  const container = useRef(null),
    instance = useRef(null),
    [error, setError] = useState('');
  useEffect(() => {
    setError('');
    let elements;
    try {
      elements = topologyElements(data, { groups, sourceNames });
    } catch {
      setError('This topology could not be displayed safely. The tables below still list every agent and link.');
      return;
    }
    const cy = cytoscape({
      container: container.current,
      elements,
      minZoom: 0.2,
      maxZoom: 2.5,
      style: STYLE,
      // Positions come from placeTopology: the same answer always draws the same picture.
      layout: { name: 'preset', padding: 30 },
    });
    cy.fit(undefined, 30);
    instance.current = cy;
    cy.on('tap', 'node:childless', event => onSelect({ type: event.target.data('kind'), id: event.target.id() }));
    cy.on('tap', 'edge', event => onSelect({ type: 'link', id: event.target.id() }));
    // A narrower pane (a phone, or a side panel opening) draws the whole fleet again.
    const resize = new ResizeObserver(() => {
      cy.resize();
      cy.fit(undefined, 30);
    });
    resize.observe(container.current);
    return () => {
      resize.disconnect();
      cy.destroy();
      instance.current = null;
    };
  }, [data, groups, sourceNames, onSelect]);
  useEffect(() => {
    instance.current
      ?.style()
      .selector('node:childless, edge.agent-link')
      .style('label', labels ? 'data(label)' : '')
      .update();
  }, [labels, data, groups]);
  useEffect(() => {
    const cy = instance.current;
    if (!cy) return;
    cy.elements().unselect();
    if (selected?.id) cy.getElementById(selected.id).select();
  }, [selected, data, groups]);
  return (
    <>
      <div
        className="graph topology-graph"
        ref={container}
        role="img"
        aria-label="Fleet topology: agents grouped by source and environment, the things they share and the declared links between them. The tables below list the same evidence."
      />
      {error && (
        <div className="graph-error">
          <Notice error>{error}</Notice>
        </div>
      )}
      <button
        className="icon-button topology-fit"
        title="Fit graph"
        aria-label="Fit graph"
        onClick={() => instance.current?.fit(undefined, 30)}
      >
        <Icon name="fit" size={16} />
      </button>
    </>
  );
}

function AgentPanel({ agent, data, onAgent }) {
  const rows = linkRows(data).filter(row => row.raw.from === agent.key || row.raw.to === agent.key);
  const iso = agent.isolation ?? {};
  const change = agent.lastChange ?? {};
  return (
    <>
      <h3>{agent.name ?? agent.agentId}</h3>
      <p>
        {FLAG_TONE[agent.dangerousThree] && (
          <Status tone={FLAG_TONE[agent.dangerousThree]}>
            {FLAG_NAME}: {agent.dangerousThree}
          </Status>
        )}{' '}
        {permissionsChanged(change) && <Status tone="blue">Permissions changed</Status>}
      </p>
      <Properties
        items={[
          ['Team', agent.teamId ?? 'Unknown'],
          ['Owner', agent.ownerName ?? agent.ownerId ?? 'Unknown'],
          ['Environments', (agent.environments ?? []).join(', ') || 'None declared'],
        ]}
      />
      <h4>Isolation</h4>
      <Properties
        items={[
          ['Network (host-declared)', networkText(iso.network)],
          ['Cloud identity', isolationText(iso.cloud_identity)],
          ['Caller principal', isolationText(iso.principal)],
          ['Credentials', isolationText(iso.credential)],
          ['MCP servers', isolationText(iso.mcp_server)],
          ['Resources', isolationText(iso.resource)],
          ['Sending out', egressText(iso.egress)],
          ['Around the guard', directAccessText(iso.egress)],
          [
            'Delegated from a task not shown',
            `${agent.delegationParentsNotShown ?? 0} (outside your view, undeclared or filtered out)`,
          ],
        ]}
      />
      <h4>Last change</h4>
      <p>{lastChangeText(change)}</p>
      {change.from && (
        <p className="fine-print">
          Between the snapshot of {displayTime(change.from)} and the one of {displayTime(change.to)}. The exact time is
          not recorded.
        </p>
      )}
      {(change.items ?? []).length > 0 && (
        <ul className="topology-list">
          {change.items.map(item => (
            <li key={item.entityId}>
              {item.kind} · {item.name} · {(item.categories ?? []).map(changeCategoryName).join(', ')}
            </li>
          ))}
          {change.total > change.items.length && <li>and {change.total - change.items.length} more</li>}
        </ul>
      )}
      <h4>Links</h4>
      {rows.length ? (
        <ul className="topology-list">
          {rows.map(row => (
            <li key={row.id}>
              {row.from} → {row.kind.toLowerCase()} → {row.to}
            </li>
          ))}
        </ul>
      ) : (
        <p className="subtle">No declared link to another visible agent or shared item.</p>
      )}
      <button
        type="button"
        className="secondary-button"
        onClick={() => onAgent({ id: agent.id, sourceId: agent.sourceId })}
      >
        Open in agent inventory
      </button>
    </>
  );
}
function HubPanel({ hub, data }) {
  const kind = HUB_KIND_NAME[hub.kind] ?? 'Shared item';
  const holders = data.links.filter(link => link.to === hub.id).map(link => data.agents.find(a => a.key === link.from));
  // The list comes from the links in this answer; a cut or compact answer may not carry them all.
  const listed = holders.filter(Boolean).length;
  return (
    <>
      <h3>
        {kind} · <Identifier value={hub.name} />
      </h3>
      <p>
        Held by {hub.agentCount} agents in your view
        {hub.agentsNotDrawn ? `, ${hub.agentsNotDrawn} of them left out by the filters` : ''}
        {hub.sensitivity ? `; sensitivity ${hub.sensitivity}` : ''}.
      </p>
      <ul className="topology-list">
        {holders.filter(Boolean).map(agent => (
          <li key={agent.key}>{agent.name ?? agent.agentId}</li>
        ))}
      </ul>
      {listed < hub.agentCount - (hub.agentsNotDrawn ?? 0) && (
        <p className="fine-print">
          This answer lists {listed} of them; narrow the view by source or environment to see every holder.
        </p>
      )}
      <p className="fine-print">
        The declarations put these agents on one {kind.toLowerCase()}, so that layer does not separate them. Whether one
        can reach what another left there depends on how the item is used.
      </p>
    </>
  );
}

/** The fleet in one picture: who shares what with whom, how isolated each agent is, and what changed. */
export function TopologyView({ sources = [], query, reportError, onAgent }) {
  const [sourceId, setSource] = useState(''),
    [environment, setEnvironment] = useState(''),
    [groups, setGroups] = useState(LINK_GROUPS.map(([id]) => id)),
    [labels, setLabels] = useState(true),
    [selected, setSelected] = useState(null),
    [attempt, setAttempt] = useState(0),
    [result, setResult] = useState({ status: 'loading' });
  useEffect(() => {
    let active = true;
    const controller = new AbortController();
    setResult({ status: 'loading' });
    setSelected(null);
    const args = { ...(sourceId ? { sourceId } : {}), ...(environment ? { environment } : {}) };
    query('get_agent_topology', args, { signal: controller.signal })
      .then(response => active && setResult({ status: 'ready', data: response.data }))
      .catch(error => {
        if (!active) return;
        setResult({ status: 'error', message: errorMessage(error) });
        reportError(error, { shown: true });
      });
    return () => {
      active = false;
      controller.abort();
    };
  }, [query, reportError, sourceId, environment, attempt]);
  const data = result.data;
  const sourceNames = useMemo(
    () => Object.fromEntries(sources.map((source, index) => [source.id, sourceOptionLabel(source, index)])),
    [sources],
  );
  // Environments seen in any answer so far, so choosing one does not hide the others.
  const [known, setKnown] = useState([]);
  useEffect(() => {
    const seen = (data?.agents ?? []).flatMap(agent => agent.environments ?? []);
    setKnown(current =>
      seen.every(item => current.includes(item)) ? current : [...new Set([...current, ...seen])].sort(),
    );
  }, [data]);
  const environments = known;
  const summary = topologySummary(data);
  const rows = useMemo(() => linkRows(data), [data]);
  const onSelect = useMemo(() => value => setSelected(value), []);
  const selectedAgent = selected?.type === 'agent' ? data?.agents.find(agent => agent.key === selected.id) : null;
  const selectedHub = selected?.type === 'hub' ? data?.hubs.find(hub => hub.id === selected.id) : null;
  const selectedLink = selected?.type === 'link' ? rows.find(row => row.id === selected.id) : null;
  return (
    <section className="wide-card topology">
      <h2>Agent topology</h2>
      <p className="subtle">
        Every visible agent in one picture, boxed by source and environment. Purple arrows are declared agent-to-agent
        links; dashed lines lead to an MCP server, identity, credential or resource that two or more agents share. A
        shared item is a place where agents are not isolated from each other.
      </p>
      <div className="inventory-filters">
        <label>
          Source
          <select
            value={sourceId}
            onChange={event => {
              // Another source has other environments: start its list and choice afresh.
              setSource(event.target.value);
              setEnvironment('');
              setKnown([]);
            }}
          >
            <option value="">All visible sources</option>
            {sources.map((source, index) => (
              <option key={source.id} value={source.id}>
                {sourceOptionLabel(source, index)}
              </option>
            ))}
          </select>
        </label>
        <label>
          Environment
          <select value={environment} onChange={event => setEnvironment(event.target.value)}>
            <option value="">All environments</option>
            {(environment && !environments.includes(environment) ? [environment, ...environments] : environments).map(
              value => (
                <option key={value} value={value}>
                  {value}
                </option>
              ),
            )}
          </select>
        </label>
        <fieldset className="topology-toggles">
          <legend>Show</legend>
          {LINK_GROUPS.map(([id, title]) => (
            <label key={id} className="checkbox-label">
              <input
                type="checkbox"
                checked={groups.includes(id)}
                onChange={event =>
                  setGroups(current => (event.target.checked ? [...current, id] : current.filter(item => item !== id)))
                }
              />
              {title}
            </label>
          ))}
        </fieldset>
      </div>
      {result.status === 'loading' ? (
        <p role="status">Loading topology…</p>
      ) : result.status === 'error' ? (
        <div>
          <Note error>{result.message}</Note>
          <button type="button" className="secondary-button" onClick={() => setAttempt(value => value + 1)}>
            Retry topology
          </button>
        </div>
      ) : (
        <>
          <div className="topology-metrics" role="status">
            <div>
              <strong>{summary.agents}</strong>
              <span>Agents</span>
            </div>
            <div>
              <strong>{summary.agentLinks}</strong>
              <span>Agent-to-agent links</span>
            </div>
            <div>
              <strong>{summary.sharedHubs}</strong>
              <span>Shared items</span>
            </div>
            <div>
              <strong>{summary.sharedIdentity}</strong>
              <span>Agents sharing an identity or credential</span>
            </div>
            <div>
              <strong>{summary.permissionChanges}</strong>
              <span>
                Permission changes in the latest snapshot
                {summary.newAgents ? ` · ${summary.newAgents} new agent${summary.newAgents === 1 ? '' : 's'}` : ''}
              </span>
            </div>
            <div>
              <strong>{summary.outsideGuard}</strong>
              <span>Agents with paths around the guard</span>
            </div>
            <div>
              <strong>{summary.openEgress}</strong>
              <span>Agents with open network egress</span>
            </div>
            <div>
              <strong>{summary.networkUnknown}</strong>
              <span>Agents whose network isolation is not fully declared</span>
            </div>
          </div>
          {data.hubLinksOmitted && (
            <Note>
              The links from agents to shared items are left out of this answer to keep it within the response limit;
              each shared item still shows how many agents hold it, and each agent's isolation says what it shares.
            </Note>
          )}
          {data.compact && (
            <Note>
              This fleet is too large for the full answer, so detail lists (recipients, change items, link evidence) are
              left out; every status and count is still here. Narrow it by source or environment for the detail.
            </Note>
          )}
          {(data.hubsTruncated || data.linksTruncated) && (
            <Note>
              The fleet has more shared items or links than one answer carries ({data.hubsTotal} items,{' '}
              {data.linksTotal} links). Narrow it by source or environment.
            </Note>
          )}
          {data.flagsUnavailable && (
            <Note>Boundary flags could not be evaluated for this many agents; all read unknown.</Note>
          )}
          <div className="topology-layout">
            <div className="graph-shell">
              <div className="graph-tools">
                <span>FLEET TOPOLOGY</span>
                <div>
                  <button className="small-button" onClick={() => setLabels(!labels)} aria-pressed={labels}>
                    Labels {labels ? 'on' : 'off'}
                  </button>
                </div>
              </div>
              <TopologyGraph
                data={data}
                groups={groups}
                labels={labels}
                sourceNames={sourceNames}
                selected={selected}
                onSelect={onSelect}
              />
              <div className="graph-legend">
                <span>
                  <i className="legend-agent" />
                  Agent
                </span>
                <span>
                  <i className="legend-flag exposed" />
                  {FLAG_NAME}: Exposed / Mitigated / Unknown
                </span>
                <span>
                  <i className="legend-changed" />
                  Permissions changed in the latest snapshot
                </span>
                <span>
                  <i className="legend-mcp" />
                  Shared MCP server
                </span>
                <span>
                  <i className="legend-identity" />
                  Shared identity, principal or credential
                </span>
                <span>
                  <i className="legend-resource" />
                  Shared resource (red border: confidential)
                </span>
                <span>
                  <i className="legend-segment" />
                  Shared network segment
                </span>
                <span>
                  <i className="legend-crossing" />
                  Declared agent-to-agent link
                </span>
                <span>
                  <i className="legend-box" />
                  Source / environment box
                </span>
              </div>
            </div>
            <aside className="evidence-panel topology-panel" aria-live="polite">
              {selectedAgent ? (
                <AgentPanel agent={selectedAgent} data={data} onAgent={onAgent} />
              ) : selectedHub ? (
                <HubPanel hub={selectedHub} data={data} />
              ) : selectedLink ? (
                <>
                  <h3>{selectedLink.kind}</h3>
                  <p>
                    {selectedLink.from} → {selectedLink.to}
                  </p>
                  {selectedLink.via && (
                    <p>
                      Evidence: {selectedLink.via}
                      {selectedLink.viaTotal > 5 ? ` and ${selectedLink.viaTotal - 5} more` : ''}
                    </p>
                  )}
                </>
              ) : (
                <p className="subtle">Select an agent, a shared item or a link to see its isolation and evidence.</p>
              )}
              <h4>Evidence, not observation</h4>
              <p className="fine-print">
                Links, shared items and network isolation are what manifests and the executor declare. They show that
                agents could exchange data, not that they did; network traffic is not observed.
              </p>
            </aside>
          </div>
          <DataTable
            title="Isolation by agent"
            rows={data.agents}
            empty="No visible agent matches."
            columns={[
              ['Agent', agent => agent.name ?? agent.agentId],
              ['Environments', agent => (agent.environments ?? []).join(', ') || 'None declared'],
              ['Flag', agent => agent.dangerousThree],
              ['Network (host-declared)', agent => networkText(agent.isolation?.network)],
              ['Cloud identity', agent => isolationText(agent.isolation?.cloud_identity)],
              ['Principal', agent => isolationText(agent.isolation?.principal)],
              ['Credentials', agent => isolationText(agent.isolation?.credential)],
              ['MCP servers', agent => isolationText(agent.isolation?.mcp_server)],
              ['Resources', agent => isolationText(agent.isolation?.resource)],
              ['Sending out', agent => egressText(agent.isolation?.egress)],
              ['Around the guard', agent => directAccessText(agent.isolation?.egress)],
              ['Last change', agent => lastChangeText(agent.lastChange)],
              [
                'Open',
                agent => (
                  <button
                    type="button"
                    className="small-button"
                    onClick={() => setSelected({ type: 'agent', id: agent.key })}
                  >
                    Show in graph
                  </button>
                ),
              ],
            ]}
          />
          {data.removedAgentsTotal > 0 && (
            <DataTable
              title="Agents removed since the previous snapshot"
              rows={data.removedAgents}
              columns={[
                ['Agent', agent => agent.name ?? agent.agentId],
                ['Team', agent => agent.teamId ?? 'Unknown'],
                ['Between', agent => `${displayTime(agent.from)} and ${displayTime(agent.to)}`],
              ]}
            />
          )}
          <DataTable
            title="Shared items"
            rows={data.hubs}
            empty="Nothing is held by two or more agents in your view."
            columns={[
              ['Kind', hub => HUB_KIND_NAME[hub.kind] ?? 'Shared item'],
              ['Name', hub => <Identifier value={hub.name} />],
              ['Agents', hub => String(hub.agentCount)],
              ['Filtered out', hub => String(hub.agentsNotDrawn ?? 0)],
              ['Sensitivity', hub => hub.sensitivity ?? '—'],
              [
                'Open',
                hub => (
                  <button
                    type="button"
                    className="small-button"
                    onClick={() => setSelected({ type: 'hub', id: hub.id })}
                  >
                    Show in graph
                  </button>
                ),
              ],
            ]}
          />
          <DataTable
            title="Links"
            rows={rows}
            empty="No declared link between visible agents, and nothing two of them share."
            columns={[
              ['From', row => row.from],
              ['Link', row => row.kind],
              ['To', row => row.to],
              ['Evidence', row => row.via || '—'],
            ]}
          />
          <ul className="fine-print">
            {(data.limitations ?? []).map(item => (
              <li key={item}>{item}</li>
            ))}
          </ul>
        </>
      )}
    </section>
  );
}
