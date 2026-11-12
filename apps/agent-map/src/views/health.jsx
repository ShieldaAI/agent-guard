import React from 'react';
import { componentHealth, displayTime } from '../view-model.mjs';
import { undeclaredActivityLabel } from '../discovery-model.mjs';
import { label } from '../labels.mjs';
import { Empty, Icon, Notice, Status } from '../components/common.jsx';
import { Identifier } from '../components/identifier.jsx';

/** Shown above the views that rely on the source list when the health read failed. */
export function HealthUnavailable({ health, onRetry }) {
  return health.status === 'unavailable' ? (
    <div className="page-error">
      <Notice>
        Inventory health is unavailable{health.message ? `: ${health.message}` : '.'} Source details below may be
        missing or out of date. The agent inventory is not affected.
      </Notice>
      <button className="secondary-button" onClick={onRetry}>
        Retry health
      </button>
    </div>
  ) : null;
}

function snapshotFreshness(source) {
  return source.stale === false ? 'Snapshot recent' : source.stale === true ? 'Snapshot stale' : 'Freshness unknown';
}

/** Capture freshness and collection coverage of each source the reader may see. */
export function Health({ sources, status }) {
  return (
    <section className="wide-card">
      <div className="section-heading">
        <div>
          <h2>Inventory health</h2>
          <p>Capture freshness and collection coverage for your authorized sources.</p>
        </div>
        <Icon name="shield" size={25} />
      </div>
      {status === 'loading' && !sources.length ? (
        <p role="status">Loading inventory health…</p>
      ) : status === 'unavailable' && !sources.length ? (
        <Empty title="Health unavailable">Health could not be read. Select Retry health above.</Empty>
      ) : sources.length ? (
        <div className="health-list">
          {sources.map(source => (
            <article className="health-item" key={source.id ?? source.sourceId}>
              <div>
                <h3>{source.tenantId ?? 'Authorized source'}</h3>
                <Identifier value={source.sourceId ?? source.id} />
              </div>
              <div>
                <span className="field-label">Snapshot captured</span>
                <strong>{displayTime(source.generatedAt)}</strong>
              </div>
              <Status tone={source.stale === false ? 'green' : 'amber'}>{snapshotFreshness(source)}</Status>
              <div className="coverage-list">
                {Object.entries(source.coverage ?? {}).map(([component, coverage]) => {
                  const state = componentHealth(coverage),
                    name = label('healthComponent', component);
                  return (
                    <section className="coverage-item" key={component} aria-label={`${name} collection`}>
                      <div>
                        <b>{name}</b>
                        <span>
                          {state.status}
                          {state.reason ? `: ${state.reason}` : ''}
                        </span>
                      </div>
                      <time dateTime={state.observedAt ?? undefined}>{state.observedLabel}</time>
                      <Status tone={state.tone}>{state.freshness}</Status>
                      {state.ageLabel && <small>{state.ageLabel}</small>}
                    </section>
                  );
                })}
                {source.undeclaredActivity && (
                  <section className="coverage-item" aria-label="Undeclared activity">
                    <div>
                      <b>{label('healthComponent', 'undeclaredActivity')}</b>
                      <span>{undeclaredActivityLabel(source.undeclaredActivity).text}</span>
                    </div>
                  </section>
                )}
              </div>
            </article>
          ))}
        </div>
      ) : (
        <Empty title="No visible sources">No published source is available in your current scope.</Empty>
      )}
      <Notice>
        Recent collection does not establish current execution permission. Provider and MCP observations have
        independent lifecycles.
      </Notice>
    </section>
  );
}
