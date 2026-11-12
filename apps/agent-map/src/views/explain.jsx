import React, { useEffect, useMemo, useRef, useState } from 'react';
import { errorMessage, initialExplanation, policyNotEvaluated } from '../view-model.mjs';
import { label } from '../labels.mjs';
import { Icon, Note, Notice, Status } from '../components/common.jsx';
import { PolicyEvidence } from '../policy-evidence.jsx';

const unique = values => [...new Set(values.filter(value => typeof value === 'string' && value))];

/** Explains one task, tool and resource selector. The pickers offer what the agent's loaded tasks and grants name. */
function Explain({ access, query, reportError, onExplained }) {
  const [form, setForm] = useState(() => initialExplanation(access)),
    [result, setResult] = useState(null),
    [error, setError] = useState(''),
    [busy, setBusy] = useState(false);
  const request = useRef(null);
  useEffect(() => () => request.current?.abort(), []);
  function updateResult(value) {
    setResult(value);
    onExplained?.(Boolean(value));
  }
  useEffect(() => {
    setForm(initialExplanation(access));
    setError('');
    updateResult(null);
  }, [access, onExplained]);
  function change(field, value) {
    updateResult(null);
    setError('');
    setForm({ ...form, [field]: value });
  }
  async function submit(event) {
    event.preventDefault();
    setBusy(true);
    setError('');
    updateResult(null);
    const controller = new AbortController();
    request.current = controller;
    try {
      const response = await query(
        'explain_access',
        { sourceId: access.agent.sourceId, ...form },
        { signal: controller.signal },
      );
      if (!controller.signal.aborted) updateResult(response.data);
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
  const grants = access.grants ?? [];
  const tools = unique(grants.map(grant => grant.tool));
  const matching = grants.filter(grant => !form.tool || grant.tool === form.tool);
  const selectors = unique((matching.length ? matching : grants).flatMap(grant => grant.resources ?? []));
  return (
    <>
      {result && (
        <PolicyEvidence
          evidence={result.externalEvidence?.policyEvidence ?? []}
          notEvaluated={policyNotEvaluated(result.externalEvidence?.policyCoverage)}
        />
      )}
      <section className="explanation-card">
        <div className="section-heading">
          <div>
            <h3>Explain declared access</h3>
            <p>Inspect one task, tool and exported resource selector.</p>
          </div>
          <span className="pill">Read only</span>
        </div>
        <form onSubmit={submit} className="explain-form">
          <label>
            Task
            <input
              list="explain-task-options"
              value={form.taskId}
              maxLength={4096}
              required
              disabled={busy}
              onChange={event => change('taskId', event.target.value)}
              placeholder="Choose or type a task ID"
            />
            <datalist id="explain-task-options">
              {(access.tasks ?? []).map(task => (
                <option key={task.id} value={task.taskId} />
              ))}
            </datalist>
          </label>
          <label>
            Tool
            <input
              list="explain-tool-options"
              value={form.tool}
              maxLength={4096}
              required
              disabled={busy}
              onChange={event => change('tool', event.target.value)}
              placeholder="Choose or type a tool name"
            />
            <datalist id="explain-tool-options">
              {tools.map(tool => (
                <option key={tool} value={tool} />
              ))}
            </datalist>
          </label>
          <label>
            Resource selector
            <input
              list="explain-resource-options"
              value={form.resourceId}
              maxLength={4096}
              required
              disabled={busy}
              onChange={event => change('resourceId', event.target.value)}
              placeholder="Choose or type a selector"
            />
            <datalist id="explain-resource-options">
              {selectors.map(selector => (
                <option key={selector} value={selector} />
              ))}
            </datalist>
          </label>
          <button className="primary-button" disabled={busy || !form.taskId}>
            {busy ? 'Checking…' : 'Explain'}
            <Icon name="arrow" size={16} />
          </button>
        </form>
        {error && <Note error>{error}</Note>}
        {result && (
          <div className="explanation-result" role="status">
            <Status tone={result.assessment === 'blocked' ? 'danger' : 'amber'}>
              {result.assessment === 'blocked' ? 'Observed blocker' : 'Execution remains unknown'}
            </Status>
            {result.blockers?.length > 0 && (
              <div>
                <h4>Known blockers</h4>
                <ul>
                  {result.blockers.map((item, i) => (
                    <li key={i}>{label('blocker', item)}</li>
                  ))}
                </ul>
              </div>
            )}
            {result.unknownChecks?.length > 0 && (
              <div>
                <h4>Still requires evaluation</h4>
                <ul>
                  {result.unknownChecks.map((item, i) => (
                    <li key={i}>{label('unknownCheck', item)}</li>
                  ))}
                </ul>
              </div>
            )}
            <p className="subtle">No action was prepared or executed.</p>
          </div>
        )}
      </section>
    </>
  );
}

/**
 * The explanation form for one agent. `grants` is the first page the Declared permissions
 * section already loaded (null while it loads); only the tasks are read here.
 */
export function AgentExplanation({ agent, grants, query, reportError, onExplained }) {
  const [tasks, setTasks] = useState(null),
    [error, setError] = useState(''),
    [attempt, setAttempt] = useState(0);
  useEffect(() => {
    let active = true;
    const controller = new AbortController();
    setTasks(null);
    setError('');
    query(
      'get_agent_inventory',
      { sourceId: agent.sourceId, agentId: agent.id ?? agent.agentId, section: 'tasks', limit: 20, offset: 0 },
      { signal: controller.signal },
    )
      .then(result => {
        if (active) setTasks(result.data.items ?? []);
      })
      .catch(failure => {
        if (active) {
          setError(errorMessage(failure));
          reportError(failure, { shown: true });
        }
      });
    return () => {
      active = false;
      controller.abort();
    };
  }, [agent, query, reportError, attempt]);
  const access = useMemo(() => (tasks && grants ? { agent, tasks, grants } : null), [agent, tasks, grants]);
  return error ? (
    <>
      <Notice error>{error}</Notice>
      <button className="secondary-button" onClick={() => setAttempt(value => value + 1)}>
        Retry explanation selectors
      </button>
    </>
  ) : access ? (
    <Explain access={access} query={query} reportError={reportError} onExplained={onExplained} />
  ) : (
    <p role="status">Loading explanation selectors…</p>
  );
}
