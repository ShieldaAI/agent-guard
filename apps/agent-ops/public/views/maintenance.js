// Maintenance: operational status, capacity, history and archiving finished requests.
import { button, empty, field, formField, lockable, node, notice, tag } from '../dom.js';
import {
  TOOL_CHANGE_KINDS,
  archiveCandidateLabel,
  blockerSentence,
  countLabel,
  date,
  quantity,
  toolHintLabel,
} from '../text.js';
import { capacityTable } from './shared.js';

function operationalPanel(ctx) {
  const { state, actions } = ctx,
    status = state.operational,
    recent = status.http.recent,
    activity = state.activity;
  const latency = recent.p95AboveMaxBucket
    ? 'Over 10 seconds'
    : recent.p95UpperBoundMs !== null
      ? `Up to ${recent.p95UpperBoundMs} ms`
      : 'No measured requests';
  return node(
    'section',
    { class: 'panel setup-wide', 'aria-label': 'Operational status' },
    node(
      'div',
      { class: 'panel-head' },
      node(
        'div',
        {},
        node('h2', {}, 'Operational status'),
        node('p', {}, `Observed ${date(status.capturedAt)}. Refresh to update.`),
      ),
      tag('Stores readable'),
    ),
    node(
      'div',
      { class: 'panel-body' },
      status.alerts.length
        ? node(
            'div',
            {},
            status.alerts.map(alert =>
              notice(
                `${alert.severity === 'critical' ? 'Action required' : 'Needs attention'}: ${alert.message}`,
                alert.severity === 'critical' ? 'error' : 'warning',
              ),
            ),
          )
        : notice('No alert threshold is exceeded right now. This is not a complete health assessment.'),
      node(
        'dl',
        { class: 'fields' },
        field('Requests awaiting review in this tenant', status.workflow.pending),
        field('Unconfirmed outcomes in this tenant', status.workflow.unconfirmed),
        field('Oldest unconfirmed request', `${Math.floor(status.workflow.oldestUnconfirmedMs / 60_000)} minutes`),
        field('Service requests · last five minutes', quantity(recent.requests)),
        field('Service errors · last five minutes', quantity(recent.serverErrors)),
        field('95th-percentile response time', latency),
      ),
      node(
        'p',
        { class: 'subtle' },
        'Request counters cover this service process, including health checks. Disk space and outside dependencies need separate monitoring.',
      ),
      node(
        'section',
        { class: 'receipt', 'aria-label': 'Activity snapshot' },
        node('h3', {}, 'Activity snapshot'),
        node(
          'p',
          { class: 'subtle' },
          'Download up to 1,000 recent events for this tenant. Older events may be absent. It does not replace confirmation records, archives or a complete audit history.',
        ),
        node(
          'div',
          { class: 'actions' },
          button('Prepare activity snapshot', actions.prepareActivity, { id: 'prepare-activity' }),
        ),
        activity &&
          node(
            'div',
            { class: 'preview' },
            node(
              'dl',
              { class: 'fields' },
              field('Exported events', activity.count),
              field('Events left out', activity.omitted),
              field('Snapshot captured', date(activity.capturedAt), { wide: true }),
              field('SHA-256 fingerprint', node('code', {}, activity.digest), { wide: true }),
            ),
            node(
              'div',
              { class: 'actions' },
              node(
                'a',
                { class: 'button', href: activity.url, download: 'agent-ops-activity.json', id: 'download-activity' },
                'Download activity JSON',
              ),
            ),
          ),
      ),
    ),
  );
}

function archivePanel(ctx) {
  const { state, actions, now } = ctx,
    maintenance = state.maintenance,
    candidates = maintenance.archiveCandidates,
    preview = state.preview;
  const selected = lockable(
    node(
      'select',
      { id: 'archive-task', required: true, onchange: event => actions.setArchiveTask(event.target.value) },
      node('option', { value: '' }, 'Choose a finished request'),
      candidates.map(item => node('option', { value: item.taskId }, archiveCandidateLabel(item))),
    ),
    !candidates.length,
  );
  selected.value = state.archiveTaskId;
  const previewed = preview && candidates.find(item => item.taskId === preview.taskId);
  const lapsed = preview && preview.expiresAt <= now;
  return node(
    'section',
    { class: 'panel' },
    node(
      'div',
      { class: 'panel-head' },
      node(
        'div',
        {},
        node('h2', {}, 'Archive finished requests'),
        node('p', {}, 'Archiving frees working records. The request and its confirmation record stay visible.'),
      ),
    ),
    node(
      'div',
      { class: 'panel-body' },
      node('p', { class: 'subtle' }, `${countLabel(maintenance.records, 'request')} kept for this tenant.`),
      maintenance.unresolvedCount > 0 &&
        notice(
          `${countLabel(maintenance.unresolvedCount, 'outcome')} ${maintenance.unresolvedCount === 1 ? 'is' : 'are'} still unconfirmed. Check whether they were applied before archiving them.`,
          'warning',
        ),
      maintenance.archiveCandidatesTruncated &&
        notice('The list shows the first 500 finished requests. Refresh after archiving to load the rest.'),
      candidates.length
        ? node(
            'form',
            { class: 'form-stack', onsubmit: actions.previewArchive },
            formField('Finished request', 'archive-task', selected),
            lockable(
              node('button', { type: 'submit', class: 'button', id: 'preview-archive' }, 'Preview archive'),
              !state.archiveTaskId,
            ),
          )
        : node(
            'p',
            { class: 'subtle' },
            'No finished requests are ready to archive. Requests that are waiting or unconfirmed stay available.',
          ),
      preview &&
        node(
          'section',
          { class: 'preview', 'aria-labelledby': 'archive-preview-heading' },
          node('h3', { id: 'archive-preview-heading', tabindex: '-1' }, 'Archive preview'),
          node(
            'dl',
            { class: 'fields' },
            field('Request', previewed ? archiveCandidateLabel(previewed) : preview.requestId, { wide: true }),
            field('Request reference', node('code', {}, preview.requestId), { wide: true }),
            field('Valid until', date(preview.expiresAt), { wide: true }),
            field('Preview fingerprint', node('code', {}, preview.digest), { wide: true }),
          ),
          preview.blockers.length > 0 &&
            node(
              'div',
              {},
              node('p', { class: 'review-note' }, 'This request cannot be archived yet:'),
              node(
                'ul',
                {},
                preview.blockers.map(code => node('li', {}, blockerSentence(code))),
              ),
            ),
          lapsed && notice('This preview expired. Preview again.', 'warning'),
          node(
            'div',
            { class: 'actions' },
            button('Archive this request', actions.applyArchive, {
              id: 'apply-archive',
              disabled: lapsed || preview.blockers.length > 0 || preview.eligibleCount === 0,
            }),
          ),
        ),
    ),
  );
}

/** One side of a change. The value is the definition's own text and enters the page as a text node. */
function toolValue(label, shown, absent) {
  return node(
    'div',
    { class: 'tool-value' },
    node('h4', {}, label),
    shown === null
      ? node('p', { class: 'subtle' }, absent)
      : [node('pre', {}, shown.text), shown.truncated && node('p', { class: 'subtle' }, 'Cut after 2,000 characters.')],
  );
}
/**
 * What changed in the service's tool definition since it was last approved. Display only: the
 * service approves its own tool at startup, so this is a record to read after an upgrade.
 */
function toolDefinitionPanel(tool) {
  const summary = {
    first_approval: 'No earlier approval is on record for this tool, so there is nothing to compare with.',
    unchanged: 'The definition is the same as the one last approved.',
    changed: 'The definition differs from the one last approved. This service approved it at startup.',
    unavailable: 'The definition differs from the one last approved, but a definition was too large to keep.',
  }[tool.status];
  return node(
    'section',
    { class: 'panel setup-wide', 'aria-label': 'Tool definition', id: 'tool-definition' },
    node(
      'div',
      { class: 'panel-head' },
      node('div', {}, node('h2', {}, 'Tool definition'), node('p', {}, 'Compared when this service started.')),
      tag(tool.status === 'changed' || tool.status === 'unavailable' ? 'Changed' : 'No change'),
    ),
    node(
      'div',
      { class: 'panel-body' },
      tool.status === 'changed' || tool.status === 'unavailable' ? notice(summary, 'warning') : notice(summary),
      node(
        'dl',
        { class: 'fields' },
        field('Tool', node('code', {}, tool.name)),
        field(
          'Last approved before this start',
          tool.approvedAt === null ? 'No approval on record' : date(tool.approvedAt),
        ),
        field('Fingerprint now', node('code', {}, tool.fingerprint), { wide: true }),
        tool.approvedFingerprint &&
          field('Fingerprint last approved', node('code', {}, tool.approvedFingerprint), { wide: true }),
      ),
      tool.changes.length > 0 &&
        node(
          'ol',
          { class: 'tool-changes', 'aria-label': 'Changed fields' },
          tool.changes.map(change =>
            node(
              'li',
              {},
              node(
                'div',
                { class: 'tool-change-head' },
                node('code', {}, change.path || '(whole definition)'),
                tag(TOOL_CHANGE_KINDS[change.kind]),
                change.hints.map(hint => node('span', { class: 'badge hint-mark' }, toolHintLabel(hint))),
              ),
              node(
                'div',
                { class: 'tool-sides' },
                toolValue('Approved', change.before, 'Not present.'),
                toolValue('Now', change.after, 'Removed.'),
              ),
            ),
          ),
        ),
      tool.truncated && notice('More fields changed than are listed here.', 'warning'),
      node(
        'p',
        { class: 'review-note' },
        'Values are the definition’s own text, shown as written. Marks such as “New input field” are automatic hints, not a verdict: an unmarked change can still matter. The comparison covers the definition only, never what the tool’s code does.',
      ),
    ),
  );
}

export function maintenanceView(ctx) {
  const { state } = ctx,
    maintenance = state.maintenance;
  if (!ctx.allowed('operator') || !maintenance || !state.operational)
    return node(
      'section',
      { class: 'panel' },
      empty('Maintenance unavailable', 'Only operators can open maintenance. Refresh to check your role.'),
    );
  const history = maintenance.history;
  return node(
    'div',
    { class: 'maintenance-grid' },
    operationalPanel(ctx),
    node(
      'section',
      { class: 'panel setup-wide' },
      node('div', { class: 'panel-head' }, node('h2', {}, 'Deployment capacity')),
      node(
        'div',
        { class: 'panel-body' },
        maintenance.capacityWarning &&
          notice(
            'The deployment is close to a capacity limit. Review usage with the deployment owner before taking on more work.',
            'warning',
          ),
        capacityTable(maintenance),
        node(
          'p',
          { class: 'subtle' },
          'Usage is from the last refresh. Ticket data is measured before encryption, not as disk usage. Archiving keeps requests and their confirmation records.',
        ),
        node(
          'p',
          { class: 'review-note' },
          'Record, size and key limits change only through a reviewed offline configuration change and a restart. The history segment limit is fixed.',
        ),
      ),
    ),
    node(
      'section',
      { class: 'panel setup-wide' },
      node('div', { class: 'panel-head' }, node('h2', {}, 'Company history')),
      node(
        'div',
        { class: 'panel-body' },
        node(
          'dl',
          { class: 'fields' },
          field('Requests moved to history for this tenant', history.archivedRequests),
          field('Committed history segments', history.segments),
          field(
            'Last history commit',
            history.lastCommittedAt === null ? 'No history committed yet' : date(history.lastCommittedAt),
          ),
          field('History operation', history.pending ? 'Pending offline recovery' : 'None pending'),
          history.commitment && field('History head fingerprint', node('code', {}, history.commitment), { wide: true }),
        ),
        node(
          'p',
          { class: 'review-note' },
          'Moving requests into company history is a reviewed offline job. This page reports what is committed locally. It does not check copies kept elsewhere, restore tests or alert delivery.',
        ),
        history.pending &&
          notice(
            'The deployment owner must finish or recover the pending history operation. Do not delete its files.',
            'warning',
          ),
      ),
    ),
    archivePanel(ctx),
    toolDefinitionPanel(maintenance.toolDefinition),
    node(
      'section',
      { class: 'panel' },
      node('div', { class: 'panel-head' }, node('h2', {}, 'Key rotation')),
      node(
        'div',
        { class: 'panel-body' },
        tag('Offline only'),
        node('p', { class: 'review-note' }, maintenance.keyRotation.message),
      ),
    ),
  );
}
