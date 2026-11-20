import { ASI, rule } from './common.js';
import type { Rule } from './common.js';
import type { Project } from '../model.js';
import { CAPABILITIES, CAPABILITY_LABELS, type Agent, type Capability } from '../types.js';
import { covers, DAY, isShipped, REVIEWS_PATH, startOfDay, type ReviewRecord } from '../reviews.js';

/** Days before review_by when the check starts saying the review is due. */
export const DUE_SOON_DAYS = 14;

const plural = (count: number, word: string) => `${count} ${word}${count === 1 ? '' : 's'}`;

/** The record that speaks for an agent: the one naming its ID, else its name, else its file. */
export function recordFor(agent: Agent, records: readonly ReviewRecord[]): ReviewRecord | undefined {
  return (
    records.find(record => record.agent === agent.id) ??
    records.find(record => record.agent === agent.name) ??
    records.find(record => record.agent === agent.location.file)
  );
}

/**
 * What an agent can do, or may do, without a person approving each use. A capability behind a
 * per-call prompt is reviewed at every call, so a review record lists only the ones that are not.
 */
export function unasked(agent: Agent): Map<Capability, 'yes' | 'unknown'> {
  const out = new Map<Capability, 'yes' | 'unknown'>();
  for (const grant of agent.grants)
    if (grant.approval === 'auto' && out.get(grant.capability) !== 'yes') out.set(grant.capability, grant.certainty);
  return out;
}

export function currentCapabilities(agent: Agent): Capability[] {
  const found = unasked(agent);
  return CAPABILITIES.filter(capability => found.has(capability));
}

function shipped(project: Project): Agent[] {
  return project.agents.filter(isShipped);
}

/** Everyone CODEOWNERS names, lower-cased: `@user`, `@org/team` and email addresses. */
function codeOwners(text: string): Set<string> {
  const out = new Set<string>();
  for (const line of text.split('\n')) {
    const body = line.replace(/(^|\s)#.*$/, '').trim();
    if (!body) continue;
    for (const token of body.split(/\s+/).slice(1)) out.add(token.toLowerCase());
  }
  return out;
}

const RENEW =
  'Review what the agent can do now (agent-guard-check lists it), set capabilities to what you approve, and move review_by.';

export const REVIEW_RULES: readonly Rule[] = [
  rule(
    {
      id: 'AGC-REV-001',
      title: 'Agent review date has passed',
      severity: 'high',
      confidence: 'high',
      owasp: [ASI.rogue],
      help: `The review_by date in ${REVIEWS_PATH} has passed, so the agent keeps its access with nobody having looked at it on schedule. The date passes without a commit, so this finding fails every pull request until the review is done, and a baseline does not silence it. In the ${DUE_SOON_DAYS} days before the date it is reported as info.`,
    },
    (project, report, context) => {
      const today = startOfDay(context.now ?? Date.now());
      for (const record of project.reviews?.records ?? []) {
        const days = Math.round((today - record.reviewByTime) / DAY);
        if (days > 0)
          report({
            message: `The review of ${record.agent} was due on ${record.reviewBy}, ${plural(days, 'day')} ago (owner ${record.owner}). Until it is reviewed, it keeps access nobody has checked on schedule.`,
            location: record.location,
            subject: `lapsed:${record.agent}:${record.reviewBy}`,
            fix: RENEW,
          });
        else if (-days <= DUE_SOON_DAYS)
          report({
            message: `The review of ${record.agent} is due on ${record.reviewBy}, ${days === 0 ? 'today' : `in ${plural(-days, 'day')}`} (owner ${record.owner}).`,
            location: record.location,
            subject: `due:${record.agent}:${record.reviewBy}`,
            severity: 'info',
            fix: RENEW,
          });
      }
    },
  ),
  rule(
    {
      id: 'AGC-REV-002',
      title: 'Agent has no review record',
      severity: 'high',
      confidence: 'high',
      owasp: [ASI.rogue],
      help: `policy.require_reviews in .agc.yaml says every agent the repository ships needs an entry in ${REVIEWS_PATH}: an owner, the capabilities the last review approved, and a review_by date. An agent without one has no one answering for it and no date when anyone looks again.`,
    },
    (project, report, context) => {
      if (!context.config.policy.requireReviews) return;
      const records = project.reviews?.records ?? [];
      for (const agent of shipped(project)) {
        if (records.some(record => covers(record, agent))) continue;
        report({
          message: `${agent.name} has no entry in ${REVIEWS_PATH}, so it has no owner and no review date.`,
          location: agent.location,
          subject: `missing:${agent.id}`,
          agent,
          fix: `Add an entry to ${REVIEWS_PATH} with agent: ${agent.location.file}, an owner, the capabilities you approve and a review_by date.`,
        });
      }
    },
  ),
  rule(
    {
      id: 'AGC-REV-003',
      title: 'Agent can do more than its review approved',
      severity: 'high',
      confidence: 'high',
      owasp: [ASI.tools, ASI.rogue],
      help: `The capabilities in an agent's ${REVIEWS_PATH} entry are what its last review approved it to do without a person approving each use (a capability behind a per-call prompt is checked at every call). A change that gives the agent more has to change that list too, so the widening shows up in the review record and is not just a line in a settings file. A capability the scanner can only call unknown is reported at medium.`,
    },
    (project, report) => {
      const records = project.reviews?.records ?? [];
      if (!records.length) return;
      for (const agent of shipped(project)) {
        const record = recordFor(agent, records);
        if (!record) continue;
        const found = unasked(agent);
        const extra = currentCapabilities(agent).filter(capability => !record.capabilities.includes(capability));
        if (!extra.length) continue;
        const certain = extra.some(capability => found.get(capability) === 'yes');
        const labels = extra.map(
          capability => `${CAPABILITY_LABELS[capability]}${found.get(capability) === 'unknown' ? ' (maybe)' : ''}`,
        );
        report({
          message: `Without asking anyone, ${agent.name} ${labels.join(', ')}: more than its review (${record.agent}, owner ${record.owner}) approved, which was ${record.capabilities.join(', ') || 'nothing'}.`,
          location: agent.location,
          subject: `exceeds:${agent.id}:${[...extra].sort().join(',')}`,
          agent,
          ...(certain ? {} : { severity: 'medium' as const }),
          fix: `Remove the extra access, or have ${record.owner} review it and add ${extra.join(', ')} to capabilities in ${REVIEWS_PATH}.`,
        });
      }
    },
  ),
  rule(
    {
      id: 'AGC-REV-004',
      title: 'Agent review date is too far away',
      severity: 'high',
      confidence: 'high',
      owasp: [ASI.rogue],
      help: `A review_by date years away turns the review into a formality. It may be at most policy.max_review_days ahead of the scan (default 365), so a renewal cannot quietly push it out of sight.`,
    },
    (project, report, context) => {
      const today = startOfDay(context.now ?? Date.now());
      const limit = context.config.policy.maxReviewDays;
      for (const record of project.reviews?.records ?? []) {
        const days = Math.round((record.reviewByTime - today) / DAY);
        if (days <= limit) continue;
        report({
          message: `The review of ${record.agent} is set for ${record.reviewBy}, ${plural(days, 'day')} away; the limit is ${plural(limit, 'day')}.`,
          location: record.location,
          subject: `far:${record.agent}:${record.reviewBy}`,
          fix: `Set review_by no more than ${plural(limit, 'day')} ahead, or raise policy.max_review_days in .agc.yaml.`,
        });
      }
    },
  ),
  rule(
    {
      id: 'AGC-REV-005',
      title: 'Review record matches no agent',
      severity: 'medium',
      confidence: 'high',
      owasp: [ASI.rogue],
      help: `An entry in ${REVIEWS_PATH} names no agent the scan found by ID, name or file. Usually the agent was moved or renamed, and its review date now guards nothing.`,
    },
    (project, report) => {
      const agents = shipped(project);
      for (const record of project.reviews?.records ?? []) {
        if (agents.some(agent => covers(record, agent))) continue;
        report({
          message: `The review record for ${record.agent} matches no agent in the repository, so its review date applies to nothing.`,
          location: record.location,
          subject: `orphan:${record.agent}`,
          fix: 'Point agent at the agent’s ID, name or defining file, or remove the entry if the agent is gone.',
        });
      }
    },
  ),
  rule(
    {
      id: 'AGC-REV-006',
      title: 'Review owner is not a code owner',
      severity: 'low',
      confidence: 'high',
      owasp: [ASI.rogue],
      help: `The owner in ${REVIEWS_PATH} appears nowhere in CODEOWNERS, so nobody asks them to review changes to the agent. It also catches an owner who has left and was removed from CODEOWNERS. Runs only when the repository has a CODEOWNERS file.`,
    },
    (project, report) => {
      if (!project.codeowners) return;
      const owners = codeOwners(project.codeowners.text);
      for (const record of project.reviews?.records ?? []) {
        if (owners.has(record.owner.toLowerCase())) continue;
        report({
          message: `${record.owner}, the owner of ${record.agent}, is not named in ${project.codeowners.path}, so they are not asked to review changes to it.`,
          location: record.location,
          subject: `owner:${record.agent}:${record.owner.toLowerCase()}`,
          fix: `Add ${record.owner} to CODEOWNERS for the agent's files, or set owner to someone who is.`,
        });
      }
    },
  ),
  rule(
    {
      id: 'AGC-REV-007',
      title: 'Review record could not be read',
      severity: 'high',
      confidence: 'high',
      owasp: [ASI.rogue],
      help: `An entry in ${REVIEWS_PATH} has no owner, no date, a date that is not YYYY-MM-DD, an unknown capability or key, or the file is not valid YAML. A record that cannot be read is never guessed at: what it would have checked is reported as unchecked.`,
    },
    (project, report) => {
      for (const item of project.reviews?.invalid ?? [])
        report({
          message: `${item.message}, so the agent it is for is not held to a review.`,
          location: item.location,
          subject: item.subject,
          fix: 'Give every entry agent, owner, review_by (YYYY-MM-DD) and capabilities.',
        });
    },
  ),
];
