import { useCallback, useEffect, useRef, useState } from 'react';
import { useSession } from './use-session.mjs';
import { NO_FILTERS, useAgentListing, useHealth, useSelectedAgent } from './use-inventory.mjs';

/**
 * The open workspace: the session, which view is open, the sidebar filters and page, what is
 * selected, and the list and health that go with them. It holds no markup, so the rules that
 * decide what a reader may still see (after sign-out, a lost session, a different session on
 * return) are in one place and testable without a browser.
 */
export function useWorkspace() {
  const [tab, setTab] = useState('inventory'),
    [filters, setFilters] = useState(NO_FILTERS),
    [offset, setOffset] = useState(0),
    [resourceOwner, setResourceOwner] = useState(null),
    [resourceSelection, setResourceSelection] = useState(null),
    [listingRevision, setListingRevision] = useState(0),
    [healthRevision, setHealthRevision] = useState(0);
  const resume = useRef(() => {});
  const resetNavigation = useCallback(() => {
    setTab('inventory');
    setFilters(NO_FILTERS);
    setOffset(0);
    setResourceOwner(null);
    setResourceSelection(null);
  }, []);
  const connection = useSession({ onClear: resetNavigation, onResume: () => resume.current() });
  const { session, reportError } = connection;
  const selected = useSelectedAgent({ session, reportError });
  const { listing, options } = useAgentListing({
    session,
    filters,
    offset,
    revision: listingRevision,
    reportError,
    onError: selected.clear,
  });
  const { health, sources } = useHealth({ session, revision: healthRevision, reportError });

  // A different filter or page shows a different list: what was selected in the old one is closed.
  const listed = JSON.stringify([filters, offset]),
    shown = useRef(listed);
  useEffect(() => {
    if (shown.current === listed) return;
    shown.current = listed;
    selected.clear();
  }, [listed, selected.clear]);
  // Signing out, losing the session or getting a different one closes the selected agent with everything else.
  useEffect(() => {
    selected.clear();
  }, [session, selected.clear]);

  // Choosing an agent (not refreshing the open one) moves focus to its heading once it opens.
  function selectAgent(agent, navigate = true) {
    if (navigate) setTab('inventory');
    connection.setError('');
    return selected.select(agent, { focus: navigate });
  }
  function refresh() {
    connection.setError('');
    setListingRevision(value => value + 1);
    setHealthRevision(value => value + 1);
    if (tab === 'inventory' && selected.selection) void selectAgent(selected.selection, false);
  }
  // A company session that was checked on return keeps its place: the list and health are read
  // again, and the open agent stays as it is (its sub-view included) until the reader refreshes it.
  resume.current = () => {
    setListingRevision(value => value + 1);
    setHealthRevision(value => value + 1);
  };
  function openTab(id) {
    // Leaving while a selection is still loading drops it; an opened agent stays selected.
    selected.cancel();
    if (!selected.access) selected.clear();
    setTab(id);
    connection.setError('');
    if (id === 'resources') {
      setResourceOwner(null);
      setResourceSelection(null);
    }
  }
  function setFilter(name, value) {
    setFilters(current => ({
      ...current,
      [name]: value,
      // The source filter belongs to an owner chosen in the Owners view; a new owner choice drops it.
      ...(name === 'owner' ? { source: '' } : {}),
    }));
    setOffset(0);
  }
  function showOwner(owner) {
    setFilters({ ...NO_FILTERS, owner: owner.ownerId, source: owner.sourceId });
    setOffset(0);
    selected.clear();
    setTab('inventory');
  }
  function showOwnerResources(owner) {
    setResourceOwner(owner);
    setResourceSelection(null);
    setTab('resources');
  }
  function showResource(resource) {
    setResourceSelection(resource);
    setResourceOwner(null);
    setTab('resources');
  }
  return {
    connection,
    session,
    reportError,
    tab,
    filters,
    offset,
    resourceOwner,
    resourceSelection,
    selected,
    listing,
    options,
    health,
    sources,
    // While a company page is away, and until its session has been checked on return, the
    // evidence must not be shown.
    covered: Boolean(session) && connection.covered,
    showHome: () => setTab('inventory'),
    openTab,
    setFilter,
    setOffset,
    selectAgent,
    refresh,
    retryHealth: () => setHealthRevision(value => value + 1),
    showOwner,
    showOwnerResources,
    showResource,
  };
}
