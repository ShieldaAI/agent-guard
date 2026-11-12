import { useCallback, useEffect, useRef, useState } from 'react';
import { flushSync } from 'react-dom';
import {
  createBearerQuerySession,
  createCompanyQuerySession,
  createQuerySession,
  endCompanySession,
  errorMessage,
  readCompanySession,
  retryCompanyLogout,
  startCompanyLogin,
  watchCompanySession,
} from '../view-model.mjs';
import { flagFilterArgs } from '../boundary-model.mjs';
import { queryDemo } from '../demo.mjs';

export const PAGE_SIZE = 20;
let workspaces = 0;
const SESSION_ENDED = 'Your company session ended or its access changed. Check sign-in to continue.';

/**
 * Everything about being connected: which sign-in the service offers, the open query session
 * (reference credential, company session or local demo), signing in and out, and keeping a
 * company session honest while the page is hidden or about to expire.
 *
 * `onClear` runs whenever the evidence must go (sign-out, a rejected credential, an ended
 * session); `onResume` runs after a returning company session was checked and is still valid.
 *
 * Two flags describe a company workspace whose page went away. `covered`: its evidence must
 * not be shown (from the moment the page is hidden until a check on return has passed).
 * `checking`: that check is running now. A demo or reference-credential workspace is never
 * covered.
 */
export function useSession({ onClear, onResume }) {
  const [session, setSession] = useState(null),
    [credential, setCredential] = useState(''),
    [connecting, setConnecting] = useState(false),
    [authentication, setAuthentication] = useState({ mode: 'pending' }),
    [error, setError] = useState(''),
    [covered, setCovered] = useState(false),
    [checking, setChecking] = useState(false),
    [expiring, setExpiring] = useState(false);
  const authenticationGeneration = useRef(0),
    pendingConnection = useRef(null),
    activeSession = useRef(null),
    authenticationRequest = useRef(null),
    logoutToken = useRef(null),
    auth = useRef(authentication),
    callbacks = useRef({ onClear, onResume });
  auth.current = authentication;
  callbacks.current = { onClear, onResume };

  const clearWorkspace = useCallback(() => {
    activeSession.current?.close();
    activeSession.current = null;
    pendingConnection.current?.close();
    pendingConnection.current = null;
    setSession(null);
    setCredential('');
    setConnecting(false);
    setCovered(false);
    setChecking(false);
    setExpiring(false);
    callbacks.current.onClear();
  }, []);
  const invalidateAuthentication = useCallback(() => {
    authenticationGeneration.current++;
    authenticationRequest.current?.abort();
    clearWorkspace();
    setAuthentication({ mode: 'unavailable' });
    setError(SESSION_ENDED);
  }, [clearWorkspace]);
  /**
   * `shown`: the caller already shows this failure next to the control that caused it, so only a
   * lost company session is acted on here.
   */
  const reportError = useCallback(
    (failure, { shown = false } = {}) => {
      if (['VIEWER_SESSION_ENDED', 'VIEWER_REQUEST_CANCELLED'].includes(failure?.code)) return;
      if (auth.current.mode === 'oidc' && [401, 403].includes(failure?.status)) {
        invalidateAuthentication();
        return;
      }
      if (!shown) setError(errorMessage(failure));
    },
    [invalidateAuthentication],
  );
  const openWorkspace = useCallback(
    async next => {
      pendingConnection.current?.close();
      pendingConnection.current = next;
      setConnecting(true);
      try {
        // The agent listing alone decides whether the workspace opens. Health loads afterwards and may fail on its own.
        const listing = await next.query('list_agents', { limit: PAGE_SIZE, offset: 0, ...flagFilterArgs('') });
        if (pendingConnection.current !== next) return;
        setCredential('');
        // The first page travels with the session, so the listing is not requested a second time.
        // `serial` names this workspace: views are keyed by it, so none outlives its session.
        const opened = { ...next, listing: listing.data, serial: ++workspaces };
        activeSession.current = opened;
        setSession(opened);
        // A company workspace that finishes opening while the page is away starts covered: the
        // watcher checks the session when the reader returns.
        if (opened.company && document.visibilityState === 'hidden') setCovered(true);
      } catch (failure) {
        next.close();
        if (pendingConnection.current === next) reportError(failure);
      } finally {
        if (pendingConnection.current === next) {
          pendingConnection.current = null;
          setConnecting(false);
        }
      }
    },
    [reportError],
  );
  const companyWorkspace = useCallback(
    value => ({
      ...createCompanyQuerySession(value.csrfToken, { onEnded: invalidateAuthentication }),
      demo: false,
      company: true,
      csrfToken: value.csrfToken,
    }),
    [invalidateAuthentication],
  );
  const bootstrap = useCallback(
    async ({ connect = true, message = '' } = {}) => {
      const run = ++authenticationGeneration.current;
      authenticationRequest.current?.abort();
      const controller = new AbortController();
      authenticationRequest.current = controller;
      clearWorkspace();
      setAuthentication({ mode: 'pending' });
      setConnecting(true);
      setError(message);
      try {
        const value = await readCompanySession({ signal: controller.signal });
        if (run !== authenticationGeneration.current || controller.signal.aborted) return;
        setAuthentication(value);
        auth.current = value;
        if (value.mode === 'oidc' && value.authenticated && connect && document.visibilityState !== 'hidden')
          await openWorkspace(companyWorkspace(value));
        return value;
      } catch {
        if (run !== authenticationGeneration.current || controller.signal.aborted) return;
        setAuthentication({ mode: 'unavailable' });
        setError('Sign-in settings could not be checked. Retry to connect, or open the local synthetic demo.');
      } finally {
        if (run === authenticationGeneration.current) {
          authenticationRequest.current = null;
          setConnecting(false);
        }
      }
    },
    [clearWorkspace, companyWorkspace, openWorkspace],
  );
  /**
   * The reader came back to a company workspace. Check the session before showing its evidence
   * again: if it still stands, the tab, filters and selection are kept and the data is refreshed;
   * if not, the evidence goes and the sign-in page explains why.
   */
  const revalidate = useCallback(async () => {
    const current = activeSession.current;
    if (!current?.company) {
      void bootstrap();
      return;
    }
    const run = ++authenticationGeneration.current;
    authenticationRequest.current?.abort();
    const controller = new AbortController();
    authenticationRequest.current = controller;
    setCovered(true);
    setChecking(true);
    try {
      const value = await readCompanySession({ signal: controller.signal });
      if (run !== authenticationGeneration.current || controller.signal.aborted) return;
      auth.current = value;
      if (value.mode !== 'oidc' || !value.authenticated) {
        clearWorkspace();
        setAuthentication(value);
        setError('Your company session ended while this page was in the background. Sign in again to continue.');
        return;
      }
      if (value.csrfToken !== current.csrfToken) {
        // The service mints this value once per session, so a different one is a different
        // sign-in, possibly by someone else. Nothing read under the old session may stay.
        clearWorkspace();
        setAuthentication(value);
        setError('Your company session changed while this page was in the background, so the view was reset.');
        await openWorkspace(companyWorkspace(value));
        return;
      }
      setAuthentication(value);
      setExpiring(false);
      callbacks.current.onResume();
    } catch {
      if (run !== authenticationGeneration.current || controller.signal.aborted) return;
      invalidateAuthentication();
    } finally {
      if (run === authenticationGeneration.current) {
        authenticationRequest.current = null;
        setChecking(false);
        // The page may have gone away again while the check ran: the evidence then stays
        // covered, and the watcher that the new session state starts checks on the next return.
        setCovered(document.visibilityState === 'hidden' && Boolean(activeSession.current?.company));
      }
    }
  }, [bootstrap, clearWorkspace, companyWorkspace, invalidateAuthentication, openWorkspace]);

  useEffect(() => {
    let message = '';
    if (window.location.pathname === '/' && window.location.search === '?auth_error=1') {
      message = 'Company sign-in could not be completed. Try again.';
      window.history.replaceState(null, '', '/');
    }
    void bootstrap({ message });
    return () => {
      authenticationGeneration.current++;
      authenticationRequest.current?.abort();
      activeSession.current?.close();
      pendingConnection.current?.close();
    };
  }, [bootstrap]);
  useEffect(() => {
    if (authentication.mode !== 'oidc' || !authentication.authenticated || session?.demo) return;
    // The evidence is hidden as the page goes away, so it is already hidden when the reader
    // returns and no frame shows it before the session has been checked.
    let watching = false;
    const stop = watchCompanySession({
      expiresAt: authentication.expiresAt,
      onExpiring: () => setExpiring(true),
      onInvalidate: () => clearWorkspace(),
      onAway: () => {
        if (!activeSession.current?.company) return;
        // Committed at once when the browser reports it; an effect cannot flush synchronously.
        if (watching) flushSync(() => setCovered(true));
        else setCovered(true);
      },
      onRevalidate: reason => {
        if (reason === 'expired') void bootstrap({ message: 'Your company session expired. Sign in again.' });
        else void revalidate();
      },
    });
    watching = true;
    return stop;
  }, [authentication, session?.demo, clearWorkspace, bootstrap, revalidate]);

  async function connect(event, demo = false) {
    event?.preventDefault();
    setError('');
    if (!demo && auth.current.mode !== 'bearer') return;
    authenticationGeneration.current++;
    authenticationRequest.current?.abort();
    authenticationRequest.current = null;
    const token = credential.trim();
    if (demo && auth.current.mode !== 'bearer')
      setAuthentication({ mode: logoutToken.current ? 'logout-unconfirmed' : 'unavailable' });
    const next = demo
      ? createQuerySession(queryDemo)
      : createBearerQuerySession(token, {
          onEnded: () => {
            clearWorkspace();
            setError('Your reference credential was rejected. Enter a valid credential to reconnect.');
          },
        });
    await openWorkspace({ ...next, demo, company: false });
  }
  async function signIn() {
    let value = auth.current;
    if (value.mode !== 'oidc') return;
    if (Date.parse(value.expiresAt) <= Date.now()) value = await bootstrap({ connect: false });
    if (value?.mode !== 'oidc') return;
    setConnecting(true);
    setError('');
    if (value.authenticated) {
      await openWorkspace(companyWorkspace(value));
      return;
    }
    const run = ++authenticationGeneration.current,
      controller = new AbortController();
    authenticationRequest.current?.abort();
    authenticationRequest.current = controller;
    try {
      const destination = await startCompanyLogin(value.csrfToken, { signal: controller.signal });
      if (run !== authenticationGeneration.current || controller.signal.aborted) return;
      window.location.assign(destination);
    } catch {
      if (run === authenticationGeneration.current && !controller.signal.aborted) {
        setAuthentication({ mode: 'unavailable' });
        setError('Company sign-in could not be started. Check sign-in and try again.');
      }
    } finally {
      if (run === authenticationGeneration.current) {
        authenticationRequest.current = null;
        setConnecting(false);
      }
    }
  }
  async function logout() {
    const retry = !activeSession.current?.company && Boolean(logoutToken.current);
    const token = activeSession.current?.company ? activeSession.current.csrfToken : logoutToken.current;
    const run = ++authenticationGeneration.current;
    authenticationRequest.current?.abort();
    authenticationRequest.current = null;
    clearWorkspace();
    setError('');
    if (!token) return;
    const controller = new AbortController();
    authenticationRequest.current = controller;
    logoutToken.current = token;
    setAuthentication({ mode: 'signing-out' });
    setConnecting(true);
    try {
      if (retry) {
        const value = await retryCompanyLogout({ signal: controller.signal });
        if (run !== authenticationGeneration.current || controller.signal.aborted) return;
        logoutToken.current = null;
        auth.current = value;
        setAuthentication(value);
        return;
      }
      await endCompanySession(token, { signal: controller.signal });
      if (run !== authenticationGeneration.current || controller.signal.aborted) return;
      logoutToken.current = null;
      await bootstrap({ connect: false });
    } catch {
      if (run !== authenticationGeneration.current || controller.signal.aborted) return;
      setAuthentication({ mode: 'logout-unconfirmed' });
      setError(
        'Local evidence was cleared, but server sign-out could not be confirmed. Retry sign-out before reconnecting.',
      );
    } finally {
      if (run === authenticationGeneration.current) {
        authenticationRequest.current = null;
        setConnecting(false);
      }
    }
  }
  return {
    session,
    authentication,
    credential,
    setCredential,
    connecting,
    checking,
    // Only a company workspace is ever covered.
    covered: covered && Boolean(session?.company),
    expiring,
    error,
    setError,
    reportError,
    connect,
    signIn,
    logout,
    checkSignIn: () => bootstrap(),
  };
}
