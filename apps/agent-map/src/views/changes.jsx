import React, { useState } from 'react';
import { useSourceChoice } from '../hooks/use-source-choice.mjs';
import { displayTime, kindName } from '../view-model.mjs';
import { sourceOptionLabel } from '../inventory-model.mjs';
import {
  CHANGE_FILTERS,
  changeCategoryLabel,
  changeIsDeclared,
  changeKindLabel,
  changeValueLabel,
} from '../boundary-model.mjs';
import { displayValue, fieldLabel } from '../labels.mjs';
import { Note } from '../components/common.jsx';
import { Identifier } from '../components/identifier.jsx';
import {
  AgentLinks,
  DataTable,
  MissingStreams,
  Pager,
  Pending,
  Properties,
  relationshipColumns,
  usePage,
} from '../components/tables.jsx';

/** One side of a changed field: the value in words, or that the item did not exist in that snapshot. */
function ChangedValue({ state, field, value, missing }) {
  return state === null ? missing : <Identifier value={changeValueLabel(field, value)} />;
}

/**
 * What changed between the two retained snapshots of one source. With `sourceId` and `agentId`
 * it is the "Agent changes" tab of one agent; otherwise the reader picks a source.
 */
export function ChangesView({ sources = [], sourceId: fixedSource, agentId, query, reportError, onAgent }) {
  const [listed, setSource] = useSourceChoice(sources),
    sourceId = fixedSource ?? listed,
    [kind, setKind] = useState('all'),
    [ready, setReady] = useState(false);
  const selectedSource = sources.find(source => source.id === sourceId);
  const page = usePage(
    query,
    'get_changes',
    { sourceId, since: 'previous', ...(agentId ? { agentId } : {}), changeKind: kind },
    reportError,
    ready && Boolean(sourceId),
  );
  return (
    <section className="wide-card">
      <h2>Snapshot comparison</h2>
      <p className="subtle">
        Inspect exact changes between authorized retained snapshots. Changed declarations do not prove effective
        permission gain or loss.
      </p>
      <form
        className="inventory-filters"
        onSubmit={event => {
          event.preventDefault();
          setReady(true);
          if (ready) page.retry();
        }}
      >
        {!fixedSource && (
          <label>
            Authorized source
            <select
              required
              value={sourceId}
              onChange={event => {
                setSource(event.target.value);
                setReady(false);
              }}
            >
              <option value="">Select source</option>
              {sources.map((source, index) => (
                <option key={source.id} value={source.id}>
                  {sourceOptionLabel(source, index)}
                </option>
              ))}
            </select>
          </label>
        )}
        <label>
          Change kind
          <select
            value={kind}
            onChange={event => {
              setKind(event.target.value);
              setReady(false);
            }}
          >
            {CHANGE_FILTERS.map(([value, title]) => (
              <option key={value} value={value}>
                {title}
              </option>
            ))}
          </select>
        </label>
        <button className="primary-button" disabled={!sourceId || page.status === 'loading'}>
          Compare snapshots
        </button>
      </form>
      {selectedSource && (
        <details className="reference-details">
          <summary>Selected source details</summary>
          <Properties
            items={[
              ['Tenant', <Identifier value={selectedSource.tenantId} />],
              ['Source reference', <Identifier value={selectedSource.sourceId ?? selectedSource.id} />],
              ['Query source identifier', <Identifier value={selectedSource.id} />],
            ]}
          />
        </details>
      )}
      {page.status === 'idle' ? (
        <p className="subtle">Choose a source and compare its retained snapshots.</p>
      ) : page.status !== 'ready' ? (
        <Pending page={page} label="changes" />
      ) : (
        <>
          {page.data.coverageGap && (
            <Note>The comparison baseline is unavailable. No complete change history can be inferred.</Note>
          )}
          <Properties
            items={[
              ['Previous capture', displayTime(page.data.from?.generatedAt)],
              ['Current capture', displayTime(page.data.to?.generatedAt)],
            ]}
          />
          {!(page.data.details ?? []).length ? (
            <p className="subtle">
              {page.data.coverageGap
                ? 'Changes cannot be determined without a retained baseline.'
                : 'No matching changes in these visible retained snapshots.'}
            </p>
          ) : (
            page.data.details.map((item, index) => (
              <article className="change-detail" key={`${item.entityId}:${index}`}>
                <h3>{item.name ?? item.entityId}</h3>
                <p>
                  {kindName(item.label)} · {changeKindLabel(item.kind)} ·{' '}
                  {displayValue((item.categories ?? []).map(changeCategoryLabel))}
                  {changeIsDeclared(item) && (
                    <>
                      {' '}
                      · <span className="pill">Declared</span>
                    </>
                  )}
                </p>
                <DataTable
                  title={`Before and after: ${item.name ?? item.entityId}`}
                  rows={(item.changedFields ?? []).map(field => ({
                    id: field,
                    field,
                    before: item.before?.properties?.[field],
                    after: item.after?.properties?.[field],
                  }))}
                  columns={[
                    ['Field', x => fieldLabel(x.field)],
                    [
                      'Before',
                      x => (
                        <ChangedValue
                          state={item.before}
                          field={x.field}
                          value={x.before}
                          missing="Not present in prior snapshot"
                        />
                      ),
                    ],
                    [
                      'After',
                      x => (
                        <ChangedValue
                          state={item.after}
                          field={x.field}
                          value={x.after}
                          missing="Not present in current snapshot"
                        />
                      ),
                    ],
                  ]}
                  empty="No displayed property change. Inspect the relationship changes below."
                />
                <h4>Affected visible agents</h4>
                <AgentLinks agents={item.affectedAgents ?? []} onAgent={onAgent} />
                {item.affectedAgentsTruncated && (
                  <Note>
                    Showing {item.affectedAgents?.length ?? 0} of {item.affectedAgentsTotal} affected visible agents.
                    Use the agent inventory to inspect the remaining agents.
                  </Note>
                )}
              </article>
            ))
          )}
          <Pager data={page.data} count={page.data.details?.length ?? 0} onPage={page.onPage} label="changes" />
          {['added', 'removed'].map(type => (
            <DataTable
              key={type}
              title={`${type === 'added' ? 'Added' : 'Removed'} relationships`}
              rows={page.data.relationships?.[type] ?? []}
              columns={relationshipColumns}
              empty={`No ${type} relationships in this comparison page.`}
            />
          ))}
          <MissingStreams />
          <p className="fine-print">Net snapshot changes are not a complete intermediate event history.</p>
        </>
      )}
    </section>
  );
}
