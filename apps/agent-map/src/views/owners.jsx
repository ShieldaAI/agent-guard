import React, { useState } from 'react';
import { LABELS, label } from '../labels.mjs';
import { Identifier } from '../components/identifier.jsx';
import { DataTable, Pager, Pending, useDebounced, usePage } from '../components/tables.jsx';

/** Owners and teams that enrolled hosts name, with links to the agents and resources each one owns. */
export function OwnersBrowse({ query, reportError, onOwner, onOwnerResources }) {
  const [search, setSearch] = useState(''),
    [kind, setKind] = useState(''),
    term = useDebounced(search);
  const page = usePage(
    query,
    'list_owners',
    { ...(term ? { search: term } : {}), ...(kind ? { kind } : {}) },
    reportError,
  );
  return (
    <section className="wide-card">
      <h2>Owners and teams</h2>
      <p className="subtle">
        Accountability asserted by enrolled hosts. Counts include only your visible relationships.
      </p>
      <div className="inventory-filters">
        <label>
          Search owners
          <input value={search} onChange={event => setSearch(event.target.value)} maxLength={256} />
        </label>
        <label>
          Owner kind
          <select value={kind} onChange={event => setKind(event.target.value)}>
            <option value="">All kinds</option>
            {Object.entries(LABELS.ownerKind).map(([value, title]) => (
              <option key={value} value={value}>
                {title}
              </option>
            ))}
          </select>
        </label>
      </div>
      {page.status !== 'ready' ? (
        <Pending page={page} label="owners" />
      ) : (
        <>
          <DataTable
            title="Visible owners"
            rows={page.data.owners ?? []}
            columns={[
              ['Owner', x => <Identifier value={x.ownerId} name={x.name} />],
              ['Kind', x => label('ownerKind', x.kind)],
              ['Source', x => <Identifier value={x.sourceId} />],
              [
                'Agents',
                x => (
                  <button className="text-link" onClick={() => onOwner(x)}>
                    View {x.agentCount} agents
                  </button>
                ),
              ],
              [
                'Resources',
                x => (
                  <button className="text-link" onClick={() => onOwnerResources(x)}>
                    View {x.resourceCount} resources
                  </button>
                ),
              ],
            ]}
            empty="No owner records are visible. Unassigned or uncollected ownership remains visible in the agent inventory."
          />
          <Pager data={page.data} count={page.data.owners?.length ?? 0} onPage={page.onPage} label="owners" />
        </>
      )}
    </section>
  );
}
