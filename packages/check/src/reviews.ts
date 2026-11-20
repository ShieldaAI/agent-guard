import { isMap, isSeq, parseDocument } from 'yaml';
import { CAPABILITIES, type Capability, type Location } from './types.js';
import { isRecord } from './text.js';

/**
 * Review records: `.agc-reviews.yaml` at the repository root says, for each agent the team ships,
 * who answers for it, what the last review approved, and when it must be reviewed again.
 *
 * ```yaml
 * reviews:
 *   - agent: .claude/settings.json   # agent ID, name, or the file that defines it
 *     owner: "@acme/platform"
 *     review_by: 2027-05-01          # YYYY-MM-DD, UTC; the day after, the check fails
 *     capabilities: [write, exec]    # what the review approved ([] for none)
 * ```
 *
 * The file is read from the commit being scanned, like agent configuration, so a pull request that
 * renews a review is judged with its new date. The limits on records (`policy.require_reviews`,
 * `policy.max_review_days`) live in `.agc.yaml`, which `--base` reads from the base commit, so a
 * change cannot loosen the rules it is judged by.
 */
export const REVIEWS_PATH = '.agc-reviews.yaml';

/**
 * Rules whose findings come from the clock, not from a change: a review date passes with no commit.
 * In a pull request they count as new whether or not the base had them, and a baseline does not
 * silence them (a baseline records the repository, and a date passing is not in the repository).
 */
export const CLOCK_RULES: ReadonlySet<string> = new Set(['AGC-REV-001']);

export interface ReviewRecord {
  /** What the entry names: an agent ID, an agent name, or the file that defines agents. */
  readonly agent: string;
  readonly owner: string;
  /** `YYYY-MM-DD`. */
  readonly reviewBy: string;
  /** Midnight UTC at the start of `reviewBy`, in milliseconds. */
  readonly reviewByTime: number;
  readonly capabilities: readonly Capability[];
  readonly location: Location;
}

export interface ReviewFile {
  readonly path: string;
  readonly records: readonly ReviewRecord[];
  /** Entries or files that could not be read. Never guessed at: each one is a finding. */
  readonly invalid: readonly { readonly message: string; readonly location: Location; readonly subject: string }[];
}

const KEYS = ['agent', 'owner', 'review_by', 'capabilities'];
const DATE = /^(\d{4})-(\d{2})-(\d{2})$/;

/** Milliseconds at midnight UTC for a real `YYYY-MM-DD` date, or undefined. */
export function parseDay(value: string): number | undefined {
  const match = DATE.exec(value);
  if (!match) return undefined;
  const time = Date.UTC(Number(match[1]), Number(match[2]) - 1, Number(match[3]));
  // Date.UTC rolls 2027-02-30 over to March: a date that does not round-trip is not a date.
  return new Date(time).toISOString().slice(0, 10) === value ? time : undefined;
}

/** The `YYYY-MM-DD` a YAML value stands for: a quoted or plain string, or a YAML 1.1 timestamp. */
function dayText(value: unknown): string | undefined {
  if (typeof value === 'string') return value.trim();
  // A timestamp with a time of day or an offset is not a day: reading it as UTC would move the date.
  if (value instanceof Date && !Number.isNaN(value.getTime()) && value.getTime() % DAY === 0)
    return value.toISOString().slice(0, 10);
  return undefined;
}

export function parseReviews(path: string, text: string): ReviewFile {
  const records: ReviewRecord[] = [];
  const invalid: { message: string; location: Location; subject: string }[] = [];
  const whole = (message: string): ReviewFile => ({
    path,
    records: [],
    invalid: [{ message, location: { file: path, line: 1 }, subject: 'file' }],
  });
  let data: unknown;
  let starts: (number | undefined)[] = [];
  try {
    const doc = parseDocument(text, { uniqueKeys: true });
    if (doc.errors.length) throw doc.errors[0];
    data = doc.toJS({ maxAliasCount: 20 });
    // Each entry's line comes from where the parser found it, not from searching for its text.
    const list = isMap(doc.contents) ? doc.contents.get('reviews', true) : undefined;
    if (isSeq(list)) starts = list.items.map(item => (item as { range?: [number] } | null)?.range?.[0]);
  } catch (error) {
    return whole(
      `${path} is not valid YAML (${error instanceof Error ? error.message.split('\n')[0] : String(error)})`,
    );
  }
  if (data === null || data === undefined) return { path, records, invalid };
  if (!isRecord(data)) return whole(`${path} must be a mapping with a reviews list`);
  const extra = Object.keys(data).find(key => key !== 'reviews');
  if (extra !== undefined) return whole(`${path}: unknown key "${extra}"`);
  const list = data['reviews'];
  if (list === undefined || list === null) return { path, records, invalid };
  if (!Array.isArray(list)) return whole(`${path}: reviews must be a list`);
  const lineAt = (offset: number | undefined) => (offset === undefined ? 1 : text.slice(0, offset).split('\n').length);
  list.forEach((entry, i) => {
    const name = isRecord(entry) && typeof entry['agent'] === 'string' ? entry['agent'].trim() : '';
    const location = { file: path, line: lineAt(starts[i]) };
    const fail = (problem: string) =>
      invalid.push({
        message: `reviews[${i}]${name ? ` (${name})` : ''}: ${problem}`,
        location,
        subject: `entry:${name || i}`,
      });
    if (!isRecord(entry)) return fail('must be a mapping with agent, owner, review_by and capabilities');
    const unknown = Object.keys(entry).find(key => !KEYS.includes(key));
    if (unknown !== undefined) return fail(`unknown key "${unknown}"`);
    if (!name) return fail('agent is required: an agent ID, an agent name, or the file that defines it');
    const owner = typeof entry['owner'] === 'string' ? entry['owner'].trim() : '';
    if (!owner) return fail('owner is required: the person or team who answers for this agent');
    const reviewBy = dayText(entry['review_by']);
    const reviewByTime = reviewBy === undefined ? undefined : parseDay(reviewBy);
    if (reviewBy === undefined || reviewByTime === undefined)
      return fail('review_by is required and must be a date written YYYY-MM-DD');
    const capabilities = entry['capabilities'];
    if (!Array.isArray(capabilities) || !capabilities.every(item => typeof item === 'string'))
      return fail(
        `capabilities is required: the capabilities the review approved, [] for none (${CAPABILITIES.join(', ')})`,
      );
    const bad = capabilities.find(item => !(CAPABILITIES as readonly string[]).includes(item));
    if (bad !== undefined) return fail(`unknown capability "${bad}" (use ${CAPABILITIES.join(', ')})`);
    if (records.some(record => record.agent === name)) return fail('another entry already names this agent');
    records.push({
      agent: name,
      owner,
      reviewBy: reviewBy!,
      reviewByTime: reviewByTime!,
      capabilities: [...new Set(capabilities as Capability[])],
      location,
    });
  });
  return { path, records, invalid };
}

interface Named {
  readonly id: string;
  readonly name: string;
  readonly location: Location;
}

/**
 * Whether a record covers an agent: by ID, by the file that defines it, or by name when no other
 * agent in `agents` has that name. A name is chosen in the file (a subagent's front matter), so one
 * shared by several agents would let a new agent borrow another's review.
 */
export function covers(record: ReviewRecord, agent: Named, agents: readonly Named[]): boolean {
  if (record.agent === agent.id || record.agent === agent.location.file) return true;
  return record.agent === agent.name && agents.filter(item => item.name === agent.name).length === 1;
}

/** How many of `agents` a record's value names by name: more than one covers none of them. */
export function sameName(record: ReviewRecord, agents: readonly Named[]): number {
  return agents.filter(
    item => item.name === record.agent && item.id !== record.agent && item.location.file !== record.agent,
  ).length;
}

/** Agents defined outside the repository (your own or managed settings) are not shipped with it. */
export function isShipped(agent: { location: Location }): boolean {
  return !/^(~|<managed>)(\/|$)/.test(agent.location.file);
}

export const DAY = 86_400_000;

/** Midnight UTC at the start of the day `now` falls on. */
export function startOfDay(now: number): number {
  return Math.floor(now / DAY) * DAY;
}
