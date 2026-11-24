import { isRecord, withoutTrailingSlashes } from './text.js';

/**
 * Read-only evidence from GitHub: whether the branch changes merge into requires a code owner's
 * approval. A CODEOWNERS entry only requests the owner's review; a ruleset or branch protection rule
 * with "Require review from Code Owners" is what makes it required.
 *
 * Active rulesets (repository and organization) can be read by anyone who can read the repository.
 * Classic branch protection settings need admin access, which the Actions token cannot be given, so
 * a branch that has classic protection and no ruleset requiring code owners reads as `unknown`.
 */
export interface BranchRules {
  /** `owner/name`. */
  readonly repo: string;
  readonly branch: string;
  /**
   * - `required`: an active ruleset or branch protection rule requires code-owner review.
   * - `not-required`: nothing that applies to the branch requires it.
   * - `unknown`: the branch has classic protection whose settings this token cannot read.
   */
  readonly codeOwnerReview: 'required' | 'not-required' | 'unknown';
  /** One sentence on what decided it. */
  readonly why: string;
  /**
   * Only when `codeOwnerReview` is `required`: whether someone may merge without it.
   * - `none`: a rule that requires code owners lets nobody bypass it.
   * - `possible`: every rule that requires code owners names someone who may bypass it.
   * - `unknown`: who may bypass could not be read (it needs admin access to the repository).
   */
  readonly codeOwnerBypass?: 'none' | 'possible' | 'unknown';
  /** One sentence on who may bypass, when `codeOwnerBypass` is set. */
  readonly bypassWhy?: string;
}

export interface BranchRulesOptions {
  readonly repo: string;
  /** Defaults to the repository's default branch. */
  readonly branch?: string;
  /** A token that can read the repository; public repositories can be read without one. */
  readonly token?: string;
  /** Defaults to https://api.github.com (GITHUB_API_URL on GitHub Enterprise Server). */
  readonly apiUrl?: string;
  readonly timeoutMs?: number;
  /** For tests; defaults to the global fetch. */
  readonly fetch?: typeof fetch;
}

export class GitHubError extends Error {
  constructor(
    message: string,
    readonly status: number | null,
  ) {
    super(message);
    this.name = 'GitHubError';
  }
}

const REPO = /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/;
const MAX_RESPONSE_BYTES = 4 * 1024 * 1024;
const MAX_PAGES = 10;

export function isRepoName(value: string): boolean {
  return REPO.test(value) && !value.split('/').some(part => part === '.' || part === '..');
}

/** The body as text, refusing more than MAX_RESPONSE_BYTES before holding it all. */
async function readCapped(response: globalThis.Response): Promise<string> {
  if (Number(response.headers.get('content-length') ?? 0) > MAX_RESPONSE_BYTES)
    throw new GitHubError('GitHub sent a response larger than 4 MiB', null);
  if (!response.body) return '';
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    size += value.byteLength;
    if (size > MAX_RESPONSE_BYTES) {
      await reader.cancel();
      throw new GitHubError('GitHub sent a response larger than 4 MiB', null);
    }
    chunks.push(value);
  }
  return Buffer.concat(chunks).toString('utf8');
}

interface Response {
  readonly status: number;
  readonly body: unknown;
  readonly next: string | undefined;
}

async function get(options: BranchRulesOptions, url: string): Promise<Response> {
  const doFetch = options.fetch ?? fetch;
  let response: globalThis.Response;
  try {
    response = await doFetch(url, {
      headers: {
        accept: 'application/vnd.github+json',
        'x-github-api-version': '2022-11-28',
        'user-agent': 'agent-guard-check',
        ...(options.token ? { authorization: `Bearer ${options.token}` } : {}),
      },
      redirect: 'manual',
      signal: AbortSignal.timeout(options.timeoutMs ?? 15_000),
    });
  } catch (error) {
    throw new GitHubError(`GitHub did not answer: ${error instanceof Error ? error.message : String(error)}`, null);
  }
  if (response.status >= 300 && response.status < 400)
    throw new GitHubError(
      `GitHub redirected ${new URL(url).pathname} (HTTP ${response.status}); was the repository renamed or moved?`,
      response.status,
    );
  const text = await readCapped(response);
  let body: unknown = null;
  try {
    body = text ? JSON.parse(text) : null;
  } catch {
    body = null;
  }
  const link = response.headers.get('link') ?? '';
  const next = /<([^>]+)>;\s*rel="next"/.exec(link)?.[1];
  return { status: response.status, body, next };
}

function failure(what: string, response: Response): GitHubError {
  const message =
    isRecord(response.body) && typeof response.body['message'] === 'string' ? response.body['message'] : '';
  const hint =
    response.status === 401
      ? ' (the token was refused)'
      : response.status === 403 || response.status === 404
        ? ' (not found, or the token cannot read it)'
        : '';
  return new GitHubError(
    `could not read ${what}: HTTP ${response.status}${hint}${message ? `: ${message.slice(0, 200)}` : ''}`,
    response.status,
  );
}

type Bypass = { readonly state: 'none' | 'possible' | 'unknown'; readonly why: string };

/**
 * Who may bypass one rule, keyed by identity (`Team:42`), with a name for each. The repository admin
 * role is `RepositoryRole:5` in rulesets (GitHub's built-in id) and is the same people classic
 * protection lets through when it does not apply to admins.
 */
type Actors = Map<string, string>;

const ADMINS = 'RepositoryRole:5';
/** Identities that are not people, so they cannot also be on a list through a team or a role. */
const NOT_PEOPLE = /^(Integration|DeployKey):/;
const NO_BYPASS: Bypass = { state: 'none', why: 'a rule that requires code owners lets nobody bypass it' };
const MEMBERSHIP: Bypass = {
  state: 'unknown',
  why: 'each rule that requires code owners lets different actors bypass it, and whether one person is on every list depends on team and role membership',
};

/** A ruleset bypass actor: its identity and, in words, who it is. Other role ids are not documented, so they are not named. */
function rulesetActor(actor: unknown): [string, string] {
  if (!isRecord(actor)) return ['?', 'someone'];
  const type = String(actor['actor_type'] ?? '?');
  const key = `${type}:${String(actor['actor_id'] ?? '')}`;
  switch (type) {
    case 'RepositoryRole':
      return [key, key === ADMINS ? 'repository admins' : 'a repository role'];
    case 'OrganizationAdmin':
      return [key, 'organization admins'];
    case 'EnterpriseOwner':
      return [key, 'enterprise owners'];
    case 'Team':
      return [key, 'a team'];
    case 'Integration':
      return [key, 'a GitHub App'];
    case 'DeployKey':
      return [key, 'deploy keys'];
    default:
      return [key, 'someone'];
  }
}

function listWords(words: Iterable<string>): string {
  const unique = [...new Set(words)];
  return unique.length <= 1 ? (unique[0] ?? '') : `${unique.slice(0, -1).join(', ')} and ${unique.at(-1)}`;
}

/**
 * Whether anyone can get past every rule that requires code owners. Every rule applies at once, so
 * only an actor on every bypass list gets through. An empty list anywhere means nobody does. Lists
 * with no actor in common still leave a person who is in one list's team and another's role, so
 * that is unknown, unless some list names only apps and deploy keys: nobody else is on it.
 */
function combine(lists: readonly Actors[], where: string): Bypass {
  if (lists.some(list => list.size === 0)) return NO_BYPASS;
  const common = [...lists[0]!.keys()].filter(key => lists.every(list => list.has(key)));
  if (common.length)
    return { state: 'possible', why: `${listWords(common.map(key => lists[0]!.get(key)!))} may bypass ${where}` };
  // A person could be on every list through different teams and roles; an app or a deploy key cannot.
  return lists.every(list => [...list.keys()].some(key => !NOT_PEOPLE.test(key))) ? MEMBERSHIP : NO_BYPASS;
}

/**
 * The bypass list of each ruleset that requires code owners. The lists are returned only to a token
 * that may edit the ruleset, so most tokens, the Actions token included, read none of them.
 */
async function rulesetLists(
  options: BranchRulesOptions,
  repoUrl: string,
  ids: readonly number[],
): Promise<{ readonly lists: readonly Actors[]; readonly unread: boolean }> {
  const lists: Actors[] = [];
  let unread = ids.length === 0 || ids.length > MAX_PAGES;
  for (const id of ids.slice(0, MAX_PAGES)) {
    let response: Response;
    try {
      response = await get(options, `${repoUrl}/rulesets/${id}`);
    } catch {
      unread = true;
      continue;
    }
    const actors = isRecord(response.body) ? response.body['bypass_actors'] : undefined;
    if (response.status !== 200 || !Array.isArray(actors)) {
      unread = true;
      continue;
    }
    lists.push(new Map(actors.map(rulesetActor)));
  }
  return { lists, unread };
}

/**
 * Who may bypass classic branch protection that requires code owners, or undefined when GitHub
 * does not say whether it applies to admins.
 */
function classicActors(settings: Record<string, unknown>): Actors | undefined {
  const reviews = settings['required_pull_request_reviews'];
  const admins = settings['enforce_admins'];
  if (!isRecord(admins)) return undefined;
  const actors: Actors = new Map();
  if (admins['enabled'] !== true) actors.set(ADMINS, 'repository admins');
  const allowances = isRecord(reviews) ? reviews['bypass_pull_request_allowances'] : undefined;
  const kinds = [
    ['users', 'User', 'named users'],
    ['teams', 'Team', 'named teams'],
    ['apps', 'Integration', 'named GitHub Apps'],
  ] as const;
  if (isRecord(allowances))
    for (const [field, type, name] of kinds) {
      const list = allowances[field];
      if (Array.isArray(list))
        list.forEach((item, index) =>
          actors.set(`${type}:${isRecord(item) ? String(item['id'] ?? `#${index}`) : `#${index}`}`, name),
        );
    }
  return actors;
}

/** Who may bypass classic protection on its own, when it is the only rule that requires code owners. */
function classicBypass(settings: Record<string, unknown>): Bypass {
  const actors = classicActors(settings);
  return actors
    ? combine([actors], 'the branch protection rule that requires it')
    : { state: 'unknown', why: 'GitHub did not say whether admins are included' };
}

/** Whether the branch's classic protection settings require code owners: the settings, or why not known. */
async function classicRequiring(
  options: BranchRulesOptions,
  repoUrl: string,
  path: string,
): Promise<Record<string, unknown> | 'none' | 'unread'> {
  try {
    const info = await get(options, `${repoUrl}/branches/${path}`);
    if (info.status !== 200 || !isRecord(info.body)) return 'unread';
    const protection = info.body['protection'];
    if (!isRecord(protection)) return info.body['protected'] === false ? 'none' : 'unread';
    if (protection['enabled'] !== true) return 'none';
    const settings = await get(options, `${repoUrl}/branches/${path}/protection`);
    if (settings.status !== 200 || !isRecord(settings.body)) return 'unread';
    const reviews = settings.body['required_pull_request_reviews'];
    return isRecord(reviews) && reviews['require_code_owner_reviews'] === true ? settings.body : 'none';
  } catch {
    return 'unread';
  }
}

/** Which rules apply to `branch`, and whether any of them requires a code owner's approval. */
export async function fetchBranchRules(options: BranchRulesOptions): Promise<BranchRules> {
  if (!isRepoName(options.repo)) throw new GitHubError(`"${options.repo}" is not an owner/name repository`, null);
  const api = withoutTrailingSlashes(options.apiUrl ?? 'https://api.github.com');
  let parsed: URL;
  try {
    parsed = new URL(api);
  } catch {
    throw new GitHubError('the GitHub API URL is not a URL', null);
  }
  if (parsed.protocol !== 'https:' || parsed.username || parsed.password || parsed.search)
    throw new GitHubError('the GitHub API URL must be https, with no credentials or query', null);
  const repoUrl = `${api}/repos/${options.repo}`;

  let branch = options.branch;
  if (!branch) {
    const repo = await get(options, repoUrl);
    if (repo.status !== 200 || !isRecord(repo.body) || typeof repo.body['default_branch'] !== 'string')
      throw failure(options.repo, repo);
    branch = repo.body['default_branch'];
  }
  // Git refuses these in branch names; `.` and `..` segments would also move the request elsewhere.
  if (
    !branch.trim() ||
    /[\0-\x1f\x7f *?[\\~^:]/.test(branch) ||
    branch.split('/').some(part => !part || part.startsWith('.'))
  )
    throw new GitHubError(`"${branch}" is not a branch name`, null);
  const path = branch.split('/').map(encodeURIComponent).join('/');

  // Active rulesets only: GitHub leaves out rulesets in "evaluate" or "disabled", which enforce nothing.
  let url: string | undefined = `${repoUrl}/rules/branches/${path}?per_page=100`;
  const rules: unknown[] = [];
  let unread = false;
  for (let page = 0; url; page++) {
    if (page === MAX_PAGES) {
      unread = true;
      break;
    }
    const response = await get(options, url);
    if (response.status !== 200 || !Array.isArray(response.body)) throw failure(`the rules for ${branch}`, response);
    rules.push(...response.body);
    // The token goes to the API host only; a next page elsewhere is left unread.
    unread = response.next !== undefined && !response.next.startsWith(`${api}/`);
    url = unread ? undefined : response.next;
  }
  const result = (codeOwnerReview: BranchRules['codeOwnerReview'], why: string, bypass?: Bypass): BranchRules => ({
    repo: options.repo,
    branch: branch!,
    codeOwnerReview,
    why,
    ...(bypass ? { codeOwnerBypass: bypass.state, bypassWhy: bypass.why } : {}),
  });
  const requiring = rules.filter(
    item =>
      isRecord(item) &&
      item['type'] === 'pull_request' &&
      isRecord(item['parameters']) &&
      item['parameters']['require_code_owner_review'] === true,
  );
  if (requiring.length) {
    const why = `an active ruleset on ${branch} requires review from code owners`;
    const ids = [
      ...new Set(
        requiring
          .map(item => (item as Record<string, unknown>)['ruleset_id'])
          .filter((id): id is number => Number.isSafeInteger(id)),
      ),
    ];
    const read = await rulesetLists(options, repoUrl, ids);
    // An empty list among those read settles it; anything else needs every list, classic's included.
    if (read.lists.some(list => list.size === 0)) return result('required', why, NO_BYPASS);
    if (read.unread || unread)
      return result('required', why, { state: 'unknown', why: 'who may bypass the rule needs admin access to read' });
    const classic = await classicRequiring(options, repoUrl, path);
    if (classic === 'unread')
      return result('required', why, {
        state: 'unknown',
        why: `the branch protection rule on ${branch} needs admin access to read`,
      });
    if (classic === 'none') return result('required', why, combine(read.lists, 'every ruleset that requires it'));
    const fromClassic = classicActors(classic);
    if (!fromClassic)
      return result('required', why, { state: 'unknown', why: 'GitHub did not say whether admins are included' });
    return result('required', why, combine([...read.lists, fromClassic], 'every rule that requires it'));
  }
  if (unread) return result('unknown', `not every rule that applies to ${branch} could be read`);

  const info = await get(options, `${repoUrl}/branches/${path}`);
  if (info.status !== 200 || !isRecord(info.body)) throw failure(`the branch ${branch}`, info);
  const protection = info.body['protection'];
  // A protected branch that does not say how (older GitHub Enterprise Server) proves nothing.
  if (!isRecord(protection) && info.body['protected'] !== false)
    return result('unknown', `GitHub did not say how ${branch} is protected`);
  const classic = isRecord(protection) && protection['enabled'] === true;
  if (!classic) return result('not-required', `no active ruleset or branch protection rule on ${branch} requires it`);

  // Classic protection: its review settings are readable with admin access only.
  const settings = await get(options, `${repoUrl}/branches/${path}/protection`);
  if (settings.status === 200 && isRecord(settings.body)) {
    const reviews = settings.body['required_pull_request_reviews'];
    return isRecord(reviews) && reviews['require_code_owner_reviews'] === true
      ? result(
          'required',
          `the branch protection rule on ${branch} requires review from code owners`,
          classicBypass(settings.body),
        )
      : result('not-required', `the branch protection rule on ${branch} does not require review from code owners`);
  }
  return result(
    'unknown',
    `${branch} has a branch protection rule whose review settings this token cannot read (they need admin access)`,
  );
}
