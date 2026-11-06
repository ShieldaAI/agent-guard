// Disposable UI contract checks. This uses synthetic API responses and no external identity/provider service.
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { readFile, mkdir, writeFile } from 'node:fs/promises';
import { createRequire } from 'node:module';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';

if (!process.argv[2]) throw new Error('Usage: node apps/agent-ops/check-browser.mjs <browser-tools-directory> [screenshot-directory] [chromium|firefox|webkit]');
const requireTools = createRequire(resolve(process.argv[2], 'package.json'));
const browserEngine = process.argv[4] ?? 'chromium';
if (!['chromium', 'firefox', 'webkit'].includes(browserEngine)) throw new Error('Unsupported browser engine');
const browserType = requireTools('playwright')[browserEngine];
const axe = await readFile(requireTools.resolve('axe-core/axe.min.js'), 'utf8');
const screenshotDirectory = process.argv[3] ? resolve(process.argv[3]) : null;
if (screenshotDirectory) await mkdir(screenshotDirectory, { recursive: true, mode: 0o700 });
const publicDirectory = fileURLToPath(new URL('./public/', import.meta.url));
const assets = new Map(await Promise.all([
  ['/', 'index.html', 'text/html'], ['/app.js', 'app.js', 'text/javascript'], ['/app.css', 'app.css', 'text/css'],
].map(async ([path, file, type]) => [path, { bytes: await readFile(join(publicDirectory, file)), type }])));
const server = createServer((request, response) => {
  const asset = assets.get(request.url);
  if (!asset) { response.writeHead(404); response.end(); return; }
  response.writeHead(200, { 'Content-Type': asset.type, 'Cache-Control': 'no-store' });
  response.end(asset.bytes);
});
await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
const origin = `http://127.0.0.1:${server.address().port}`;
const csrf = 'synthetic-csrf-reference';
const now = Date.now();
let signedIn = false;
let requestFailure = 0;
let mutationErrorCode;
let receiptAvailable = false;
let archiveBlocked = true;
let dropApprovalResponse = true;
let operatorRoles = ['requester', 'reviewer', 'operator'];
let recoveryMode = 'current-state-mirror';
let historyCapacity = { committed: 7998, reserved: 1, total: 7999, limit: 10_000 };
const limits = { maxTickets: 1000, maxRequests: 8000, maxBackendBytes: 32 * 1_048_576, maxLedgerBytes: 32 * 1_048_576, maxRetainedKeys: 8 };
const counts = { preparations: 0, approvals: 0, denials: 0, reconciliations: 0, backendWrites: 0, archives: 0 };
const tickets = [
  { id: '123', title: 'Restore monthly report access', status: 'open', version: 3 },
  { id: '456', title: 'Correct the invoice notification', status: 'open', version: 1 },
];
const requests = [
  { id: 'review-123', ticketId: '123', title: tickets[0].title, tenantId: 'northstar', beforeStatus: 'open', afterStatus: 'resolved',
    resourceVersion: 3, digest: 'a'.repeat(64), expiresAt: now + 900_000, state: 'pending', createdAt: now - 120_000 },
  { id: 'recovery-456', ticketId: '456', title: tickets[1].title, tenantId: 'northstar', beforeStatus: 'open', afterStatus: 'resolved',
    resourceVersion: 1, digest: 'b'.repeat(64), expiresAt: now - 60_000, state: 'unconfirmed', createdAt: now - 240_000 },
];
const metadata = { csrfToken: csrf, publicAuthIssuer: 'https://identity.fixture.example', authorizationOrigins: ['https://identity.fixture.example'] };
const session = () => signedIn
  ? { ...metadata, authenticated: true, expiresAt: now + 1_800_000, operator: { id: 'operator-fixture', name: 'Morgan Lee', tenantId: 'northstar', roles: operatorRoles } }
  : { ...metadata, authenticated: false };

let browser;
try {
  browser = await browserType.launch();
  const page = await browser.newPage({ locale: 'en-US', viewport: { width: 1365, height: 950 } });
  page.setDefaultTimeout(10_000);
  const pageErrors = [], scanned = [];
  page.on('pageerror', error => { pageErrors.push(error.message); console.error(error.message); });
  await page.route('**/*', async route => {
    const request = route.request();
    const url = new URL(request.url());
    const reply = value => route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(value) });
    if (url.origin === 'https://identity.fixture.example') {
      signedIn = true;
      // WebKit cannot fulfill an intercepted route with a redirect status.
      // This synthetic IdP page only returns to the disposable UI host; the
      // companion service harness exercises real HTTP OAuth redirects.
      await route.fulfill({ status: 200, contentType: 'text/html',
        body: `<!doctype html><title>Synthetic sign-in</title><script>location.replace(${JSON.stringify(origin)})</script>` });
      return;
    }
    if (url.origin !== origin || !/^\/(api|auth)\//.test(url.pathname)) { await route.continue(); return; }
    if (request.method() === 'POST') assert.equal(request.headers()['x-csrf-token'], csrf);
    const body = request.method() === 'POST' ? request.postDataJSON() : null;
    if (mutationErrorCode && request.method() === 'POST' && url.pathname === '/api/requests') {
      const code = mutationErrorCode; mutationErrorCode = undefined;
      await route.fulfill({ status: 409, contentType: 'application/json', body: JSON.stringify({ error: { code } }) }); return;
    }
    if (url.pathname === '/api/session') { await reply(session()); return; }
    if (url.pathname === '/auth/login') {
      await reply({ authorizationUrl: 'https://identity.fixture.example/authorize?response_type=code&state=synthetic' }); return;
    }
    if (url.pathname === '/auth/logout') { signedIn = false; await reply({ signedOut: true }); return; }
    if (requestFailure) {
      const status = requestFailure;
      requestFailure = 0;
      await route.fulfill({ status, contentType: 'text/plain', body: 'unavailable' });
      return;
    }
    assert.equal(signedIn, true);
    if (['/api/tickets', '/api/requests'].includes(url.pathname) && request.method() === 'GET') {
      const kind = url.pathname.slice(5), rows = kind === 'tickets' ? tickets : requests;
      const offset = Number(url.searchParams.get('offset') ?? 0), limit = Number(url.searchParams.get('limit') ?? 500);
      const selected = rows.slice(offset, offset + limit);
      await reply({ [kind]: selected, allowedStatuses: ['open', 'resolved'], offset, limit, total: rows.length,
        nextOffset: offset + selected.length < rows.length ? offset + selected.length : null, truncated: selected.length < rows.length }); return;
    }
    if (url.pathname === '/api/requests') {
      counts.preparations++;
      const ticket = tickets.find(item => item.id === body.ticketId);
      const prepared = { id: `prepared-${counts.preparations}`, tenantId: 'northstar', ticketId: ticket.id, title: ticket.title,
        beforeStatus: ticket.status, afterStatus: body.status, resourceVersion: ticket.version,
        digest: 'c'.repeat(64), expiresAt: Date.now() + 300_000, createdAt: Date.now(), state: 'pending' };
      requests.unshift(prepared);
      await reply({ request: prepared }); return;
    }
    const decision = url.pathname.match(/^\/api\/requests\/([^/]+)\/(approve|deny|reconcile)$/);
    if (decision) {
      const item = requests.find(item => item.id === decodeURIComponent(decision[1]));
      const ticket = tickets.find(ticket => ticket.id === item.ticketId);
      if (decision[2] === 'approve') {
        assert.equal(body.digest, item.digest);
        counts.approvals++;
        counts.backendWrites++;
        ticket.status = item.afterStatus;
        ticket.version++;
        item.state = 'completed';
        item.receipt = { operationId: `operation-${item.id}`, status: ticket.status, version: ticket.version, recordedAt: Date.now() };
        if (dropApprovalResponse) { dropApprovalResponse = false; await route.abort('connectionreset'); return; }
      } else if (decision[2] === 'deny') {
        assert.equal(body.digest, item.digest);
        counts.denials++;
        item.state = 'denied';
      } else {
        assert.deepEqual(body, {});
        counts.reconciliations++;
        if (receiptAvailable) {
          item.state = 'completed';
          item.receipt = { operationId: 'operation-recovery-original', status: 'resolved', version: 2, recordedAt: now - 180_000 };
        } else {
          await route.fulfill({ status: 409, contentType: 'application/json', body: JSON.stringify({ error: { code: 'RECEIPT_NOT_FOUND' } }) }); return;
        }
      }
      await reply({ request: item }); return;
    }
    if (url.pathname === '/api/maintenance') {
      await reply({ archiveCandidates: [{ taskId: 'settled-task', label: 'Completed reporting task' }], archiveCandidatesTruncated: true,
        limits, records: requests.length, recordLimit: limits.maxRequests, usage: { tickets: 820, requests: 42, receipts: 20, backendBytes: 1_048_576 }, capacityWarning: true,
        statistics: { ledgerBytes: 524_288, ledgerByteLimit: limits.maxLedgerBytes },
        historyCapacity,
        history: { archivedRequests: '123', segments: 2, lastCommittedAt: now - 60_000, commitment: 'e'.repeat(64), pending: false, mode: 'reviewed-offline' },
        keyRotation: { state: 'offline_required', keyId: 'ledger-key-generation-2', message: 'Stop the executor and use the host rotation CLI. Verify the new key before removing recovery material.' } }); return;
    }
    if (url.pathname === '/api/status') {
      assert.equal(operatorRoles.includes('operator'), true);
      await reply({ schemaVersion: 1, capturedAt: Date.now(), scope: { tenantId: 'northstar', workflow: 'tenant', capacity: 'deployment', http: 'deployment' },
        service: { ready: true }, workflow: { requests: requests.length, pending: 0, unconfirmed: 0, oldestUnconfirmedMs: 0 },
        http: { recent: { requests: 20, serverErrors: 0, p95UpperBoundMs: 250 } }, alerts: [] }); return;
    }
    if (url.pathname === '/api/audit/export') {
      assert.equal(operatorRoles.includes('operator'), true); assert.deepEqual(body, {});
      const payload = { schemaVersion: 1, kind: 'agent-ops-activity-snapshot', tenantId: 'northstar', capturedAt: Date.now(),
        coverage: { kind: 'bounded_activity_only', completeHistory: false, omittedRetainedEvents: 2, historicalDropCount: 'unknown' },
        events: [{ at: now, event: 'DENIED', requestId: 'prepared-1', operatorId: 'operator-fixture' }] };
      const content = JSON.stringify(payload) + '\n';
      await reply({ filename: 'agent-ops-activity.json', content, bytes: Buffer.byteLength(content), digest: createHash('sha256').update(content).digest('hex'), eventCount: 1, completeHistory: false }); return;
    }
    if (url.pathname === '/api/setup') {
      assert.equal(operatorRoles.includes('operator'), true);
      await reply({ deployment: 'self-hosted', identity: { issuer: metadata.publicAuthIssuer, callbackUrl: 'https://ops.fixture.example/auth/callback' },
        recovery: recoveryMode === 'unverified' ? { mode: 'unverified', verifiedAt: null }
          : { mode: recoveryMode, executorMirror: recoveryMode === 'current-state-mirror', backendMirror: recoveryMode === 'current-state-mirror', historyMirror: recoveryMode === 'current-state-mirror', verifiedAt: now },
        data: { kind: 'local-tickets', tickets: tickets.length, requests: requests.length, receipts: 20 }, limits, historyCapacity, usage: { tickets: 820, requests: 42, receipts: 20, backendBytes: 1_048_576 }, keyring: { keyCount: 5, maxKeys: 8 },
        checks: [{ id: 'owner', label: 'Storage ownership', status: 'ok', message: 'Encrypted stores are owned by this deployment.' },
          { id: 'preflight', label: 'Host preflight', status: 'warning', message: 'Repeat preflight after changing host configuration.' }],
        commands: [{ label: 'Check host configuration', command: 'node apps/agent-ops/cli.mjs preflight --config PATH' },
          { label: 'Preview company ticket import', command: 'node apps/agent-ops/cli.mjs import-tickets --config PATH --tickets PATH' }] }); return;
    }
    if (url.pathname === '/api/maintenance/archive/preview') {
      assert.equal(body.taskId, 'settled-task');
      await reply({ preview: { id: 'archive-preview', taskId: body.taskId, digest: 'd'.repeat(64), eligibleCount: 4, retainedCount: 2,
        expiresAt: Date.now() + 300_000, blockers: archiveBlocked ? ['An unresolved operation still references this task.'] : [] } }); return;
    }
    if (url.pathname === '/api/maintenance/archive/apply') {
      assert.deepEqual(body, { id: 'archive-preview', digest: 'd'.repeat(64) });
      assert.equal(archiveBlocked, false);
      counts.archives++;
      await reply({ archivedCount: 4 }); return;
    }
    throw new Error(`Unexpected fixture route ${url.pathname}`);
  });
  const button = name => page.getByRole('button', { name, exact: typeof name === 'string' });
  const heading = name => page.getByRole('heading', { name, exact: true });
  const scan = async name => {
    await page.evaluate(axe);
    const violations = await page.evaluate(async () => (await window.axe.run({
      runOnly: { type: 'tag', values: ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'] },
    })).violations.map(item => ({ id: item.id, targets: item.nodes.map(node => node.target) })));
    assert.deepEqual(violations, [], name);
    scanned.push(name);
    if (screenshotDirectory) await page.screenshot({ path: join(screenshotDirectory, `${name}.png`), fullPage: true });
  };

  await page.goto(origin);
  await button('Sign in with company account').waitFor();
  await scan('sign-in');
  await button('Sign in with company account').focus();
  await page.keyboard.press('Enter');
  await button('Approve and submit once').waitFor();
  await page.getByText('Morgan Lee', { exact: true }).waitFor();
  await scan('exact-review');
  await button('Approve and submit once').click();
  await heading('Refresh to load current state').waitFor();
  assert.equal(await button('Approve and submit once').count(), 0);
  assert.equal(counts.approvals, 1);
  await scan('interrupted-response');
  await button('Refresh').click();
  await page.getByRole('region', { name: 'Backend receipt' }).waitFor();
  assert.equal(counts.backendWrites, 1);
  await scan('confirmed-receipt');

  await page.locator('#nav-tickets').click();
  await page.getByLabel('Requested status').selectOption('open');
  await button('Prepare review').click();
  await button('Deny request').waitFor();
  await button('Deny request').click();
  await page.getByText('The reviewer denied this prepared change.', { exact: true }).waitFor();
  assert.equal(counts.backendWrites, 1);
  await scan('denied-request');

  await page.locator('#request-recovery-456').click();
  await scan('unconfirmed-outcome');
  await button('Check backend receipt').click();
  await page.getByText('A backend receipt is still unavailable. Keep this request unresolved and contact its operator.', { exact: true }).waitFor();
  assert.equal(counts.backendWrites, 1);
  await button('Refresh').click();
  await button('Check backend receipt').waitFor();
  receiptAvailable = true;
  await button('Check backend receipt').click();
  await page.getByText('operation-recovery-original', { exact: true }).waitFor();
  assert.equal(counts.backendWrites, 1);
  assert.equal(counts.reconciliations, 2);

  await page.locator('#nav-maintenance').click();
  await page.getByText(/task selector shows a bounded selection of 500/).waitFor();
  if (screenshotDirectory) await page.screenshot({ path: join(screenshotDirectory, 'maintenance-before-preview.png'), fullPage: true });
  await page.getByLabel('Task', { exact: true }).selectOption('settled-task');
  await button('Preview archive').click();
  await page.getByText('An unresolved operation still references this task.', { exact: true }).waitFor();
  assert.equal(await button('Archive 4 eligible tasks').isDisabled(), true);
  await scan('archive-blocked');
  archiveBlocked = false;
  await button('Preview archive').click();
  await button('Archive 4 eligible tasks').click();
  await page.getByText('4 tasks archived.', { exact: true }).waitFor();
  assert.equal(counts.archives, 1);
  assert.equal(await page.locator('input[type=password]').count(), 0);
  await scan('maintenance');
  await button('Prepare activity snapshot').click();
  await page.getByText('Omitted retained events', { exact: true }).waitFor();
  await scan('activity-snapshot');
  const activityDownload = page.waitForEvent('download');
  await page.getByRole('link', { name: 'Download activity JSON', exact: true }).click();
  const activity = JSON.parse(await readFile(await (await activityDownload).path(), 'utf8'));
  assert.equal(activity.tenantId, 'northstar'); assert.equal(activity.coverage.completeHistory, false);
  assert.equal(activity.events[0].event, 'DENIED');
  await page.getByText('820', { exact: true }).waitFor();
  await page.getByText('Local history head fingerprint', { exact: true }).waitFor();
  await page.getByText('e'.repeat(64), { exact: true }).waitFor();
  assert.equal(await page.getByText('No history committed yet', { exact: true }).count(), 0);
  for (const [total, stateName] of [[8000, 'warning'], [9500, 'critical'], [10_000, 'full']]) {
    historyCapacity = { committed: total - 1, reserved: 1, total, limit: 10_000 };
    await button('Refresh').click();
    await page.getByRole('row', { name: `History segments (committed + reserved) ${total.toLocaleString('en-US')} 10,000 · fixed`, exact: true }).waitFor();
    await page.getByText(`Deployment-wide history: ${(total - 1).toLocaleString('en-US')} committed + 1 reserved = ${total.toLocaleString('en-US')} segments. Pending compaction reserves its slot before creating history.`, { exact: true }).waitFor();
    await page.getByText(total < 9500 ? /History has reached 80%/ : total < 10_000 ? /History recovery capacity is nearly exhausted/ : /History recovery capacity is exhausted/).waitFor();
    await page.getByText('This fixed recovery limit includes every tenant. The configure-limits command cannot raise it.', { exact: true }).waitFor();
    await scan(`history-capacity-${stateName}`);
  }
  historyCapacity = { committed: 7998, reserved: 1, total: 7999, limit: 10_000 };
  await button('Refresh').click();
  await page.locator('#nav-setup').click();
  await heading('Your company workspace').waitFor();
  await page.getByText('https://ops.fixture.example/auth/callback', { exact: true }).waitFor();
  await page.getByText('Current-state recovery enrolled', { exact: true }).waitFor();
  assert.equal(await page.locator('input').count(), 0);
  await scan('self-hosted-setup');
  recoveryMode = 'not-enrolled';
  await button('Refresh').click();
  await page.getByText('Current-state recovery not enrolled', { exact: true }).waitFor();
  await page.getByText(/A cold checkpoint becomes stale/).waitFor();
  await scan('legacy-recovery-setup');
  recoveryMode = 'unverified';
  await button('Refresh').click();
  await page.getByText('Recovery enrollment not verified here', { exact: true }).waitFor();
  await scan('unverified-recovery-setup');
  recoveryMode = 'current-state-mirror';

  const savedTickets = tickets.splice(0);
  await button('Refresh').click();
  await page.locator('#nav-tickets').click();
  await heading('No tickets enrolled yet').waitFor();
  await button('Open setup guide').focus();
  await page.keyboard.press('Enter');
  await page.getByText(/No company tickets are enrolled in this tenant/).waitFor();
  await scan('empty-company-setup');
  tickets.push(...savedTickets);

  const savedRequests = [...requests];
  tickets.push(...Array.from({ length: 503 }, (_, index) => ({ id: `company-${index}`, title: `Company ticket ${index}`, status: 'open', version: 1 })));
  requests.push(...Array.from({ length: 503 }, (_, index) => ({ ...savedRequests[0], id: `history-${index}`, title: `Retained request ${index}`, state: 'denied' })));
  await button('Refresh').click();
  await page.locator('#nav-tickets').click();
  await page.getByText('1–500 of 505 tickets', { exact: true }).waitFor();
  await button('Next tickets').click();
  await page.getByText('501–505 of 505 tickets', { exact: true }).waitFor();
  await page.getByRole('button', { name: /Company ticket 502/ }).click();
  await page.getByText('Company ticket 502', { exact: true }).last().waitFor();
  assert.equal(await button('Next tickets').isDisabled(), true);
  await scan('later-ticket-page');
  await page.locator('#nav-requests').click();
  await button('Next requests').click();
  await page.getByText('501–506 of 506 requests', { exact: true }).waitFor();
  await page.locator('#request-history-502').click();
  await page.getByRole('heading', { name: 'Retained request 502', exact: true }).waitFor();
  await scan('later-request-page');
  await button('Previous requests').click();
  await page.getByText('1–500 of 506 requests', { exact: true }).waitFor();
  tickets.splice(savedTickets.length);
  requests.splice(savedRequests.length);
  await button('Refresh').click();
  await page.locator('#nav-tickets').click();
  mutationErrorCode = 'LIMITS_BELOW_USAGE';
  await button('Prepare review').click();
  await page.getByText('A configured storage limit was reached. Refresh to check the request outcome. The deployment owner must review and adjust limits offline.', { exact: true }).waitFor();
  await heading('Refresh to load current state').waitFor();
  assert.equal(counts.preparations, 1);
  assert.equal(counts.backendWrites, 1);
  await scan('configured-capacity-reached');
  await button('Refresh').click();

  await page.setViewportSize({ width: 375, height: 812 });
  for (const view of ['requests', 'tickets', 'maintenance', 'setup']) {
    await page.locator(`#nav-${view}`).click();
    assert.equal(await page.evaluate(() => document.documentElement.scrollWidth > innerWidth), false, view);
    const bounds = await page.locator(`#nav-${view}`).boundingBox();
    assert.ok(bounds.x >= 0 && bounds.x + bounds.width <= 375, view);
  }
  await scan('mobile-setup');
  await page.locator('#nav-maintenance').click();
  await scan('mobile-maintenance');
  await page.locator('#nav-requests').click();
  requests[0].state = 'pending';
  requests[0].expiresAt = Date.now() - 1;
  await button('Refresh').click();
  await page.locator('#request-prepared-1').click();
  await page.getByText('This review expired. Prepare a new request using the current ticket.', { exact: true }).waitFor();
  assert.equal(await button('Approve and submit once').count(), 0);
  await page.getByText('1–3 of 3 requests', { exact: true }).waitFor();
  await scan('expired-review');
  requests[0].state = 'review_required';
  delete requests[0].digest;
  await button('Refresh').click();
  await page.getByText('This preparation can no longer be approved. Prepare a new request using the current ticket.', { exact: true }).waitFor();
  assert.equal(await button('Approve and submit once').count(), 0);
  await scan('restart-requires-review');

  requestFailure = 503;
  await button('Refresh').click();
  await heading('Refresh to load current state').waitFor();
  assert.equal(await page.getByText(tickets[0].title, { exact: true }).count(), 0);
  await scan('service-unavailable');
  await button('Refresh').click();
  await page.locator('#request-prepared-1').waitFor();
  requestFailure = 403;
  await button('Refresh').click();
  await button('Check session').waitFor();
  assert.equal(await page.getByText('Morgan Lee', { exact: true }).count(), 0);
  assert.equal(await page.getByText('northstar', { exact: true }).count(), 0);
  await scan('permission-ended');
  operatorRoles = ['requester'];
  await button('Check session').click();
  await heading('Recent requests').waitFor();
  assert.equal(await page.locator('#nav-maintenance').count(), 0);
  assert.equal(await page.locator('#nav-setup').count(), 0);
  await button('Sign out').click();
  await button('Sign in with company account').waitFor();
  assert.deepEqual(pageErrors, []);
  const report = { kind: 'synthetic-operator-ui-contract', browserEngine, browserVersion: browser.version(), axe: await page.evaluate(() => window.axe.version),
    scanned, mobileViews: 4, pagedTickets: 505, pagedRequests: 506, ...counts, automaticResubmissions: 0, pageErrors: 0 };
  if (screenshotDirectory) await writeFile(join(screenshotDirectory, 'browser-results.json'), JSON.stringify(report, null, 2) + '\n');
  console.log(JSON.stringify(report));
} finally {
  try { await browser?.close(); } finally { await new Promise(resolve => server.close(resolve)); }
}
