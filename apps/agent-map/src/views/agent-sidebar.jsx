import React, { useEffect, useId, useState } from 'react';
import { activeFilterCount } from '../view-model.mjs';
import { ownershipLabel } from '../inventory-model.mjs';
import { FLAG_FILTERS, flagsUnavailableLabel } from '../boundary-model.mjs';
import { LABELS } from '../labels.mjs';
import { Icon } from '../components/common.jsx';
import { Pager } from '../components/tables.jsx';
import { FlagBadge, FlagLegend } from '../boundaries.jsx';

const sameAgent = (a, b) => Boolean(a && b) && a.id === b.id && a.sourceId === b.sourceId;

/** One picker of the Filters panel: a labelled select whose first option clears the filter. */
function FilterSelect({ title, label, value, onChange, all, choices }) {
  return (
    <label>
      {title}
      <select aria-label={label} value={value} onChange={event => onChange(event.target.value)}>
        <option value="">{all}</option>
        {choices.map(([choice, text]) => (
          <option key={choice} value={choice}>
            {text}
          </option>
        ))}
      </select>
    </label>
  );
}

/**
 * A filter the reader may type: any exact value is accepted, and the values seen so far are
 * offered as suggestions. An empty box clears the filter.
 */
function FilterInput({ title, label, value, onChange, placeholder, choices }) {
  const list = useId();
  return (
    <label>
      {title}
      <input
        aria-label={label}
        list={list}
        value={value}
        placeholder={placeholder}
        maxLength={4096}
        autoComplete="off"
        spellCheck={false}
        onChange={event => onChange(event.target.value)}
      />
      <datalist id={list}>
        {choices.map(choice => (
          <option key={choice} value={choice} />
        ))}
      </datalist>
    </label>
  );
}

/**
 * The agent list with its search and filters. The filters sit behind a "Filters" disclosure so
 * the list itself stays in view; it opens by itself when a filter is set from another view.
 */
export function AgentSidebar({ listing, filters, onFilter, onClearOwner, options, selection, onSelect, onPage }) {
  const { agents, page, state, message, refreshing } = listing;
  const active = activeFilterCount(filters);
  const [open, setOpen] = useState(active > 0);
  // A filter set elsewhere (for example "View agents" in Owners) is shown, not hidden.
  useEffect(() => {
    if (filters.owner) setOpen(true);
  }, [filters.owner]);
  const filtered = active > 0 || Boolean(filters.search);
  return (
    <aside className="agent-sidebar" aria-label="Agents">
      <div className="sidebar-title">
        <h2>Agents</h2>
        <span className="count">{state === 'ready' ? agents.length : '—'}</span>
      </div>
      <div className="search-field">
        <Icon name="search" size={17} />
        <input
          aria-label="Search visible agents"
          placeholder="Search agents…"
          value={filters.search}
          onChange={event => onFilter('search', event.target.value)}
          maxLength={256}
        />
      </div>
      <details className="filter-panel" open={open} onToggle={event => setOpen(event.currentTarget.open)}>
        <summary>
          Filters{active > 0 ? ` (${active})` : ''}
          {active > 0 && <span className="visually-hidden"> active</span>}
        </summary>
        <div className="filter-fields">
          <FilterInput
            title="Owner ID"
            label="Filter by owner ID"
            value={filters.owner}
            onChange={value => onFilter('owner', value)}
            placeholder="Any owner"
            choices={options.owners}
          />
          <FilterInput
            title="Environment"
            label="Filter by environment"
            value={filters.environment}
            onChange={value => onFilter('environment', value)}
            placeholder="Any environment"
            choices={options.environments}
          />
          <FilterSelect
            title="Ownership status"
            label="Ownership status"
            value={filters.ownership}
            onChange={value => onFilter('ownership', value)}
            all="All ownership states"
            choices={Object.entries(LABELS.ownershipFilter)}
          />
          <FilterSelect
            title="Agent lifecycle"
            label="Agent lifecycle"
            value={filters.lifecycle}
            onChange={value => onFilter('lifecycle', value)}
            all="All lifecycle states"
            choices={['active', 'inactive', 'retired', 'unknown'].map(value => [value, LABELS.lifecycle[value]])}
          />
          <FilterSelect
            title="Dangerous three flag"
            label="Dangerous three flag"
            value={filters.flag}
            onChange={value => onFilter('flag', value)}
            all={FLAG_FILTERS[0][1]}
            choices={FLAG_FILTERS.slice(1)}
          />
          <p className="fine-print">
            Type an exact owner ID or environment. The suggestions come from the agents loaded so far; any other value
            can be typed, and the Owners view lists every owner.
          </p>
        </div>
      </details>
      {filters.source && (
        <p className="fine-print">
          Owner source filter active.{' '}
          <button className="text-link" onClick={onClearOwner}>
            Clear owner filter
          </button>
        </p>
      )}
      <FlagLegend />
      {page.flagsUnavailable && (
        <p className="notice" role="status">
          {flagsUnavailableLabel(page.flagsUnavailable)}
        </p>
      )}
      <div className="agent-list" aria-busy={state === 'loading'}>
        {state === 'loading' && !(refreshing && agents.length) ? (
          <p className="sidebar-empty" role="status">
            Loading agents…
          </p>
        ) : state === 'error' ? (
          <div className="sidebar-empty" role="status">
            <p>Inventory could not be loaded. Select Refresh evidence to retry.</p>
            {message && <p>{message}</p>}
          </div>
        ) : agents.length ? (
          agents.map(agent => (
            <button
              aria-pressed={sameAgent(selection, agent)}
              className={`agent-card ${sameAgent(selection, agent) ? 'selected' : ''}`}
              key={`${agent.sourceId}-${agent.id}`}
              onClick={() => onSelect(agent)}
            >
              <span className="agent-avatar">
                <Icon name="network" size={19} />
              </span>
              <span className="agent-card-copy">
                <strong>{agent.name ?? agent.agentId}</strong>
                <small>
                  {agent.teamId ?? 'No team'}
                  <span>·</span>
                  {agent.environments?.[0] ?? 'Environment unknown'}
                </small>
                <span className="agent-owner">{ownershipLabel(agent)}</span>
                <FlagBadge value={agent.boundaryFlags} />
              </span>
              <Icon name="arrow" size={14} />
            </button>
          ))
        ) : filtered ? (
          <p className="sidebar-empty">No agents match these visible filters.</p>
        ) : (
          <div className="sidebar-empty">
            <p>No agents are on the map yet.</p>
            <p>
              An agent appears here once a host manifest declares it and the collector has published a snapshot that
              your scope can read. Activity that no manifest declares is listed under Discovery.
            </p>
          </div>
        )}
      </div>
      {state === 'ready' && <Pager data={page} count={agents.length} onPage={onPage} label="agents" />}
      <div className="sidebar-footer">
        <Icon name="lock" size={14} />
        <span>Filtered by server-side access rules</span>
      </div>
    </aside>
  );
}
