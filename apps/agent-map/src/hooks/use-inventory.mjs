import { useCallback, useEffect, useRef, useState } from 'react';
import { agentOptions, errorMessage, readInventoryHealth } from '../view-model.mjs';
import { flagFilterArgs } from '../boundary-model.mjs';
import { PAGE_SIZE } from './use-session.mjs';

export const NO_FILTERS = Object.freeze({
  search: '',
  owner: '',
  environment: '',
  ownership: '',
  lifecycle: '',
  flag: '',
  source: '',
});
const EMPTY_PAGE = Object.freeze({ offset: 0, limit: PAGE_SIZE, total: 0 });
const NO_OPTIONS = Object.freeze({ owners: [], environments: [] });
/** Typing in the search box (and every other filter change) settles this long before a listing is sent. */
export const LISTING_DEBOUNCE_MS = 200;

/** The `list_agents` arguments for the sidebar's filters and page. */
export function listingArgs(filters, offset) {
  return {
    ...(filters.search ? { search: filters.search } : {}),
    ...(filters.owner ? { ownerId: filters.owner } : {}),
    ...(filters.environment ? { environment: filters.environment } : {}),
    ...(filters.source ? { sourceId: filters.source } : {}),
    ...(filters.ownership ? { ownershipStatus: filters.ownership } : {}),
    ...(filters.lifecycle ? { lifecycleState: filters.lifecycle } : {}),
    ...flagFilterArgs(filters.flag),
    offset,
    limit: PAGE_SIZE,
  };
}

const NO_LISTING = Object.freeze({ agents: [], page: EMPTY_PAGE, state: 'ready', message: '' });
/**
 * What the agent list shows the moment a session opens: the first page that connecting already
 * loaded, or "loading" when it has none. Never an empty inventory, which would read as a fact.
 * Without a session there is nothing to list.
 */
export function openingListing(session) {
  if (!session) return { listing: NO_LISTING, options: NO_OPTIONS };
  if (!session.listing) return { listing: { ...NO_LISTING, state: 'loading' }, options: NO_OPTIONS };
  const agents = session.listing.agents ?? [];
  return { listing: { agents, page: session.listing, state: 'ready', message: '' }, options: agentOptions(agents) };
}

/**
 * One page of agents for the current filters. The page that connecting already loaded is used
 * as it is; a failure is reported as shown, because the sidebar shows it where the list would be.
 *
 * What is held belongs to one session. Under any other session the hook answers with what that
 * session opens with, in the same render: a list is never drawn under a session that did not read it.
 */
export function useAgentListing({ session, filters, offset, revision, reportError, onError }) {
  const [held, setHeld] = useState(() => ({ session, ...openingListing(session) }));
  const adopted = useRef(null),
    failed = useRef(onError);
  failed.current = onError;
  const key = JSON.stringify(listingArgs(filters, offset));
  useEffect(() => {
    setHeld(value => (value.session === session ? value : { session, ...openingListing(session) }));
    if (!session) {
      adopted.current = null;
      return;
    }
    // Connecting already loaded this first page with the default filters.
    if (session.listing && adopted.current !== session) {
      adopted.current = session;
      return;
    }
    adopted.current = session;
    let active = true;
    const controller = new AbortController();
    const update = change => setHeld(value => (value.session === session ? { ...value, ...change(value) } : value));
    update(value => ({ listing: { ...value.listing, state: 'loading', message: '' } }));
    const timer = setTimeout(() => {
      session
        .query('list_agents', JSON.parse(key), { signal: controller.signal })
        .then(result => {
          if (!active) return;
          const agents = result.data.agents ?? [];
          update(value => ({
            listing: { agents, page: result.data, state: 'ready', message: '' },
            options: agentOptions(agents, value.options),
          }));
        })
        .catch(failure => {
          if (!active) return;
          update(() => ({
            listing: { agents: [], page: EMPTY_PAGE, state: 'error', message: errorMessage(failure) },
          }));
          failed.current?.();
          reportError(failure, { shown: true });
        });
    }, LISTING_DEBOUNCE_MS);
    return () => {
      active = false;
      controller.abort();
      clearTimeout(timer);
    };
  }, [session, key, revision, reportError]);
  const shown = held.session === session ? held : openingListing(session);
  return { listing: shown.listing, options: shown.options };
}

const NO_HEALTH = Object.freeze({ health: Object.freeze({ status: 'loading' }), sources: Object.freeze([]) });
/**
 * Source health, read on its own: it can fail (and be retried) without closing the workspace.
 * Like the listing, what is held belongs to one session and is not shown under another.
 */
export function useHealth({ session, revision, reportError }) {
  const [held, setHeld] = useState(() => ({ session, ...NO_HEALTH }));
  useEffect(() => {
    setHeld(value => (value.session === session ? value : { session, ...NO_HEALTH }));
    if (!session) return;
    let active = true;
    const controller = new AbortController();
    const update = change => setHeld(value => (value.session === session ? { ...value, ...change(value) } : value));
    update(value => ({ health: { ...value.health, status: 'loading' } }));
    readInventoryHealth(session.query, { signal: controller.signal }).then(next => {
      if (!active) return;
      update(() => ({
        health: { status: next.status, message: next.message },
        ...(next.status === 'ready' ? { sources: next.sources } : {}),
      }));
      if (next.status !== 'ready' && [401, 403].includes(next.error?.status)) reportError(next.error);
    });
    return () => {
      active = false;
      controller.abort();
    };
  }, [session, revision, reportError]);
  const shown = held.session === session ? held : NO_HEALTH;
  return { health: shown.health, sources: shown.sources };
}

/**
 * The agent the reader opened: its overview read, with only the latest request counting. A
 * failed or interrupted selection does not stay highlighted, and its message is shown where
 * the agent would have opened.
 *
 * `focusRequest` is a ref: true while a selection that asked for it (`select(agent, { focus })`)
 * is waiting to open, so the detail view can move focus to the agent's name. The view clears it
 * when it takes focus; a selection that fails, is cancelled or is cleared drops it, so a later
 * agent never takes focus the reader did not ask for.
 */
export function useSelectedAgent({ session, reportError }) {
  const [owner, setOwner] = useState(null),
    [selection, setSelection] = useState(null),
    [access, setAccess] = useState(null),
    [busy, setBusy] = useState(false),
    [error, setError] = useState('');
  const generation = useRef(0),
    request = useRef(null),
    focusRequest = useRef(false);
  const cancel = useCallback(() => {
    request.current?.abort();
    generation.current++;
    focusRequest.current = false;
    setBusy(false);
  }, []);
  const clear = useCallback(() => {
    cancel();
    setOwner(null);
    setSelection(null);
    setAccess(null);
    setError('');
  }, [cancel]);
  const select = useCallback(
    async (agent, { focus = false } = {}) => {
      if (!session) return;
      request.current?.abort();
      const controller = new AbortController();
      request.current = controller;
      const run = ++generation.current;
      focusRequest.current = focus;
      setOwner(session);
      setSelection(agent);
      setAccess(null);
      setBusy(true);
      setError('');
      try {
        const result = await session.query(
          'get_agent_inventory',
          { sourceId: agent.sourceId, agentId: agent.id ?? agent.agentId, section: 'overview' },
          { signal: controller.signal },
        );
        if (run === generation.current) setAccess(result);
      } catch (failure) {
        if (run === generation.current) {
          focusRequest.current = false;
          setSelection(null);
          if (!['VIEWER_SESSION_ENDED', 'VIEWER_REQUEST_CANCELLED'].includes(failure?.code))
            setError(errorMessage(failure));
          reportError(failure, { shown: true });
        }
      } finally {
        if (run === generation.current) setBusy(false);
      }
    },
    [session, reportError],
  );
  // What was opened under another session is not this session's to show.
  const mine = owner === session;
  return {
    selection: mine ? selection : null,
    access: mine ? access : null,
    busy: mine && busy,
    error: mine ? error : '',
    select,
    cancel,
    clear,
    focusRequest,
  };
}
