// Words shown to people, built only from fields the service validated. Pure: no DOM.
import { ARCHIVE_BLOCKERS } from './contract.js';

export const STATE_LABELS = Object.freeze({
  pending: 'Awaiting review',
  completed: 'Completed',
  denied: 'Denied',
  withdrawn: 'Withdrawn',
  expired: 'Expired',
  changed: 'Ticket changed',
  unconfirmed: 'Outcome unconfirmed',
  failed: 'Not applied',
  review_required: 'Needs a new request',
});
export const stateLabel = state => STATE_LABELS[state] ?? 'Unknown';

const STATUS_WORDS = Object.freeze({ open: 'open', resolved: 'resolved' });
export const statusWord = status => STATUS_WORDS[status] ?? 'unknown';
export const statusLabel = status => statusWord(status).replace(/^./, letter => letter.toUpperCase());

/**
 * One plain sentence saying what the request does to its ticket, in the tense its state calls
 * for. `state` is the state on screen (a pending request past its deadline reads as expired).
 */
export function effectSentence(request, state = request.state) {
  const ticket = `Ticket ${request.ticketId} “${request.title}”`,
    change = `from ${statusWord(request.beforeStatus)} to ${statusWord(request.afterStatus)}`;
  if (state === 'pending') return `${ticket} will change ${change}.`;
  if (state === 'completed') return `${ticket} was changed ${change}.`;
  if (state === 'unconfirmed') return `${ticket} may have changed ${change}. The outcome is not confirmed yet.`;
  return `${ticket} would have changed ${change}. Nothing was changed.`;
}

/** "3 min 20 s", "45 s" or "2 h 5 min" for a remaining time in milliseconds. */
export function duration(milliseconds) {
  const seconds = Math.max(0, Math.ceil(milliseconds / 1000)),
    hours = Math.floor(seconds / 3600),
    minutes = Math.floor((seconds % 3600) / 60);
  if (hours) return `${hours} h ${minutes} min`;
  if (minutes) return `${minutes} min ${seconds % 60} s`;
  return `${seconds} s`;
}
export const countdown = (expiresAt, now) => (expiresAt > now ? `expires in ${duration(expiresAt - now)}` : 'expired');

export function requester(request) {
  if (request.requesterKind === 'agent') return `${request.requesterId} (agent)`;
  if (request.requesterKind === 'person') return `${request.requesterId} (person)`;
  return request.requesterId; // Recorded before the service stored who asked.
}

export function date(value) {
  return Number.isFinite(value)
    ? new Intl.DateTimeFormat(undefined, {
        month: 'short',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit',
        timeZoneName: 'short',
      }).format(new Date(value))
    : 'Unavailable';
}

export function countLabel(count, noun) {
  return `${count} ${noun}${count === 1 ? '' : 's'}`;
}

export function quantity(value, bytes = false) {
  if (!Number.isSafeInteger(value) || value < 0) return 'Not reported';
  if (!bytes) return new Intl.NumberFormat().format(value);
  const divisor = value >= 1_048_576 ? 1_048_576 : value >= 1024 ? 1024 : 1;
  const unit = divisor === 1_048_576 ? 'MiB' : divisor === 1024 ? 'KiB' : 'B';
  return `${new Intl.NumberFormat(undefined, { maximumFractionDigits: 2 }).format(value / divisor)} ${unit}`;
}

/** A finished request in the archive list: ticket, outcome, who asked, when, and its reference. */
export function archiveCandidateLabel(candidate) {
  return `Ticket ${candidate.ticketId} · ${stateLabel(candidate.state)} · requested by ${candidate.requesterId} · ${date(candidate.createdAt)} · ${candidate.requestId}`;
}

export const blockerSentence = code =>
  Object.hasOwn(ARCHIVE_BLOCKERS, code) ? ARCHIVE_BLOCKERS[code] : `It cannot be archived yet (${code}).`;
