import React from 'react';
import { displayTime, policyEvidenceRows } from './view-model.mjs';

/** A separate observation layer: never style a candidate as a granted permission. */
export function PolicyEvidence({ evidence, graph = null, compact = false }) {
  let rows;
  try { rows = policyEvidenceRows(evidence ?? [], graph); }
  catch { return <section className="policy-evidence" aria-label="IAM policy evidence"><h3>IAM policy evidence</h3><p role="status">Policy evidence could not be displayed safely. Access remains unknown.</p></section>; }
  return <section className={`policy-evidence ${compact ? 'compact' : ''}`} aria-label="IAM policy evidence">
    <div className="policy-heading"><div><h3>IAM policy evidence</h3><p>Current observations for the exact task and host bindings.</p></div><span className="policy-assessment">Access unknown</span></div>
    {rows.length ? <div className="policy-rows">{rows.map((row, index) => <article className="policy-row" key={`${row.taskId}-${row.executionBindingId}-${row.resourceBindingId}-${row.action}-${index}`}>
      <div className="policy-row-heading"><strong>{row.action}</strong><span className="policy-state">{row.label}</span></div>
      {!compact && <dl className="policy-context"><div><dt>Task</dt><dd>{row.task}</dd></div><div><dt>Deployment</dt><dd>{row.deployment}</dd></div>
        <div><dt>Execution binding</dt><dd>{row.execution}</dd></div><div><dt>Bound target</dt><dd>{row.target}</dd></div>
        <div><dt>Host scope</dt><dd>{row.bindingScope} · {row.resourceKind}</dd></div><div><dt>Policy observed</dt><dd><time dateTime={row.observedAt ?? undefined}>{displayTime(row.observedAt)}</time></dd></div></dl>}
      {row.candidates.map(candidate => <div className="policy-candidate-detail" key={candidate.relationship}>
        <p>Bucket-summary evidence; the original object or prefix restriction still applies.</p>
        {candidate.hasCondition ? <div><strong>Unresolved condition keys</strong><ul className="condition-keys">{candidate.conditionKeys.map((key, index) => <li key={`${key}-${index}`}><code>{key}</code></li>)}</ul></div> : <p>No condition on the observed candidate path. Other authorization checks remain unknown.</p>}
      </div>)}
      {!row.candidates.length && <p className="policy-gap">No candidate is shown. This observation does not establish denial.</p>}
    </article>)}</div> : <p className="policy-empty">No policy evidence was collected for these visible bindings. Access remains unknown.</p>}
    {!compact && <p className="policy-footnote">Policy candidates do not authorize execution. Session and resource policies, organization controls and request-time context still require evaluation.</p>}
  </section>;
}
