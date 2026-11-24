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

/** Who a ruleset bypass actor is, in words. Repository role ids are GitHub's built-in roles. */
function actorName(actor: unknown): string {
  if (!isRecord(actor)) return 'someone';
  const id = actor['actor_id'];
  switch (actor['actor_type']) {
    case 'RepositoryRole':
      return id === 5
        ? 'repository admins'
        : id === 4
          ? 'anyone with write access'
          : id === 2
            ? 'maintainers'
            : 'a repository role';
    case 'OrganizationAdmin':
      return 'organization admins';
    case 'EnterpriseOwner':
      return 'enterprise owners';
    case 'Team':
      return 'a team';
    case 'Integration':
      return 'a GitHub App';
    case 'DeployKey':
      return 'deploy keys';
    default:
      return 'someone';
  }
}

function listWords(words: readonly string[]): string {
  const unique = [...new Set(words)];
  return unique.length <= 1 ? (unique[0] ?? '') : `${unique.slice(0, -1).join(', ')} and ${unique.at(-1)}`;
}

/**
 * Whether the rulesets that require code owners let anyone bypass them. Their bypass lists are
 * returned only to a token that may edit the ruleset, so most tokens, the Actions token included,
 * learn `unknown`. One ruleset nobody may bypass is enough: rules from every ruleset apply together.
 */
async function rulesetBypass(options: BranchRulesOptions, repoUrl: string, ids: readonly number[]): Promise<Bypass> {
  if (!ids.length) return { state: 'unknown', why: 'GitHub did not say which ruleset requires it' };
  const who: string[] = [];
  let unread = false;
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
    if (!actors.length) return { state: 'none', why: 'a ruleset that requires code owners lets nobody bypass it' };
    who.push(...actors.map(actorName));
  }
  if (unread || ids.length > MAX_PAGES)
    return { state: 'unknown', why: 'who may bypass the ruleset needs admin access to read' };
  return { state: 'possible', why: `${listWords(who)} may bypass the ruleset that requires it` };
}

/** Whether classic branch protection settings that require code owners let anyone bypass them. */
function classicBypass(settings: Record<string, unknown>): Bypass {
  const reviews = settings['required_pull_request_reviews'];
  const admins = settings['enforce_admins'];
  const allowances = isRecord(reviews) ? reviews['bypass_pull_request_allowances'] : undefined;
  const who: string[] = [];
  if (isRecord(allowances)) {
    if (Array.isArray(allowances['users']) && allowances['users'].length) who.push('named users');
    if (Array.isArray(allowances['teams']) && allowances['teams'].length) who.push('named teams');
    if (Array.isArray(allowances['apps']) && allowances['apps'].length) who.push('named GitHub Apps');
  }
  if (!isRecord(admins)) return { state: 'unknown', why: 'GitHub did not say whether admins are included' };
  if (admins['enabled'] !== true) who.unshift('repository admins');
  return who.length
    ? { state: 'possible', why: `${listWords(who)} may bypass the branch protection rule that requires it` }
    : { state: 'none', why: 'the branch protection rule that requires it applies to admins too, and allows no bypass' };
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
    const bypass = await rulesetBypass(options, repoUrl, ids);
    if (bypass.state !== 'possible') return result('required', why, bypass);
    // Classic protection applies as well; if it requires code owners with no bypass, that holds.
    try {
      const info = await get(options, `${repoUrl}/branches/${path}`);
      const protection = isRecord(info.body) ? info.body['protection'] : undefined;
      if (isRecord(protection) && protection['enabled'] === true) {
        const settings = await get(options, `${repoUrl}/branches/${path}/protection`);
        if (settings.status === 200 && isRecord(settings.body)) {
          const reviews = settings.body['required_pull_request_reviews'];
          if (isRecord(reviews) && reviews['require_code_owner_reviews'] === true) {
            const classic = classicBypass(settings.body);
            if (classic.state === 'none') return result('required', why, classic);
          }
        }
      }
    } catch {
      // The ruleset's answer stands.
    }
    return result('required', why, bypass);
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
