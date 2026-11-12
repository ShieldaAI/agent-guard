import React, { useEffect, useId, useState } from 'react';
import { errorMessage, kindName } from '../view-model.mjs';
import { debounced, pageInfo, relationshipLabel } from '../inventory-model.mjs';
import { Note } from './common.jsx';
import { Identifier } from './identifier.jsx';

export function Pager({ data, count, onPage, label = 'results', busy = false }) {
  const page = pageInfo(data, count);
  return (
    <div className="inventory-pagination" aria-label={`${label} pages`}>
      <span aria-live="polite">{page.label}</span>
      <button
        type="button"
        disabled={busy || page.previous === null}
        aria-label={`Previous ${label} page`}
        onClick={() => onPage(page.previous)}
      >
        Previous
      </button>
      <button
        type="button"
        disabled={busy || page.next === null}
        aria-label={`Next ${label} page`}
        onClick={() => onPage(page.next)}
      >
        Next
      </button>
      {page.incomplete && <span className="fine-print">Incomplete results. Narrow the filters.</span>}
    </div>
  );
}
/**
 * One paged read, 20 rows at a time. A failure is shown where the rows would be (see `Pending`),
 * so it is reported as already shown: the caller only ends the session if access was refused.
 */
export function usePage(query, operation, args, reportError, enabled = true) {
  const key = JSON.stringify(args),
    [page, setPage] = useState({ key, offset: 0 }),
    [attempt, setAttempt] = useState(0),
    [result, setResult] = useState(null);
  const offset = page.key === key ? page.offset : 0;
  const requestKey = `${key}:${offset}:${attempt}`;
  useEffect(() => {
    if (!enabled) return;
    let active = true;
    const controller = new AbortController();
    setResult({ key: requestKey, status: 'loading' });
    query(operation, { ...JSON.parse(key), offset, limit: 20 }, { signal: controller.signal })
      .then(response => {
        if (active) setResult({ key: requestKey, status: 'ready', data: response.data });
      })
      .catch(error => {
        if (active) {
          setResult({ key: requestKey, status: 'error', message: errorMessage(error) });
          reportError(error, { shown: true });
        }
      });
    return () => {
      active = false;
      controller.abort();
    };
  }, [query, operation, key, offset, attempt, enabled, reportError]);
  const current = enabled && result?.key === requestKey ? result : null;
  return {
    data: current?.data,
    status: current?.status ?? (enabled ? 'loading' : 'idle'),
    message: current?.message,
    onPage: value => setPage({ key, offset: value }),
    retry: () => setAttempt(value => value + 1),
  };
}
/** The value once typing has paused, so a search sends one query instead of one per key. */
export function useDebounced(value) {
  const [settled, setSettled] = useState(value);
  useEffect(() => {
    const call = debounced(setSettled);
    call(value);
    return call.cancel;
  }, [value]);
  return settled;
}
/** A page that is loading, or its error with a retry, in the place its rows will take. */
export function Pending({ page, label }) {
  return page.status === 'error' ? (
    <div>
      <Note error>{page.message}</Note>
      <button type="button" className="secondary-button" onClick={page.retry}>
        Retry {label}
      </button>
    </div>
  ) : (
    <p role="status">Loading {label}…</p>
  );
}
export function DataTable({ title, rows, columns, empty = 'No visible records in this captured section.' }) {
  const hintId = useId();
  if (!rows.length) return <p className="subtle">{empty}</p>;
  return (
    <>
      <p id={hintId} className="table-scroll-hint">
        Scroll horizontally for more columns. Keyboard users can focus the table and use arrow keys.
      </p>
      <div
        className="evidence-table-scroll"
        tabIndex="0"
        role="region"
        aria-label={`${title} table`}
        aria-describedby={hintId}
      >
        <table className="evidence-table">
          <caption>{title}</caption>
          <thead>
            <tr>
              {columns.map(([name]) => (
                <th scope="col" key={name}>
                  {name}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {rows.map((item, index) => (
              <tr key={`${item.id ?? item.entityId ?? index}:${index}`}>
                {columns.map(([name, read]) => (
                  <td key={name}>{read(item)}</td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </>
  );
}
export function Properties({ items }) {
  return (
    <dl className="inventory-properties">
      {items.map(([name, value]) => (
        <div key={name}>
          <dt>{name}</dt>
          <dd>{value}</dd>
        </div>
      ))}
    </dl>
  );
}
/** One end of a relationship: its name, what kind of thing it is, and its identifier. */
function Endpoint({ name, label, id }) {
  return (
    <>
      <strong>{name ?? kindName(label)}</strong>
      {label && <small className="reference-kind">{kindName(label)}</small>}
      <Identifier value={id} />
    </>
  );
}
export const relationshipColumns = [
  ['From', x => <Endpoint name={x.sourceName} label={x.sourceLabel} id={x.source} />],
  ['Relationship', x => relationshipLabel(x.kind)],
  ['To', x => <Endpoint name={x.targetName} label={x.targetLabel} id={x.target} />],
];
export function AgentLinks({ agents, onAgent }) {
  return agents.length ? (
    <ul className="agent-links">
      {agents.map(x => (
        <li key={`${x.sourceId}:${x.id}`}>
          <button className="text-link" onClick={() => onAgent(x)}>
            {x.name ?? x.agentId ?? x.id}
          </button>
        </li>
      ))}
    </ul>
  ) : (
    <p className="subtle">No visible agent relationships were collected. This does not prove access is denied.</p>
  );
}
export function MissingStreams() {
  return (
    <Note>
      Approval events, request-time decisions, backend receipts and external policy history are not collected. A
      declared grant or mapped policy candidate does not establish current execution permission.
    </Note>
  );
}
