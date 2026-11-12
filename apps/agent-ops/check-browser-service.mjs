// Real disposable HTTPS service, encrypted stores, OIDC exchange and browser UI.
// Only the identity provider and the post-commit failure are local test fixtures.
import assert from 'node:assert/strict';
import { readFile, mkdir, writeFile } from 'node:fs/promises';
import { createRequire } from 'node:module';
import { join, resolve } from 'node:path';
import { httpsSetup } from './test/helpers.mjs';
import { openMaintenance } from './runtime.mjs';

if (!process.argv[2])
  throw new Error(
    'Usage: node apps/agent-ops/check-browser-service.mjs <browser-tools-directory> [screenshot-directory] [chromium|firefox|webkit]',
  );
const requireTools = createRequire(resolve(process.argv[2], 'package.json'));
const browserEngine = process.argv[4] ?? 'chromium';
if (!['chromium', 'firefox', 'webkit'].includes(browserEngine)) throw new Error('Unsupported browser engine');
const browserType = requireTools('playwright')[browserEngine];
const axe = await readFile(requireTools.resolve('axe-core/axe.min.js'), 'utf8');
const screenshotDirectory = process.argv[3] ? resolve(process.argv[3]) : null;
if (screenshotDirectory) await mkdir(screenshotDirectory, { recursive: true, mode: 0o700 });
const cleanup = [];
let browser,
  page,
  loseCommitResponse = false;
try {
  const fixture = await httpsSetup(
    { after: callback => cleanup.push(callback) },
    {
      afterCommit: () => {
        if (loseCommitResponse) throw new Error('Synthetic response loss after durable commit');
      },
      server: { company: { id: 'acme', name: 'Acme operations' } },
    },
  );
  fixture.provider.controls.authorizeOverrides = { subject: 'owner' };
  browser = await browserType.launch();
  // Browser-only exception for the disposable self-signed fixture certificate.
  // The service OIDC client still verifies its configured local CA.
  page = await browser.newPage({ ignoreHTTPSErrors: true, locale: 'en-US', viewport: { width: 1365, height: 950 } });
  page.setDefaultTimeout(12_000);
  // Schedule the real expiry watcher at a pointer boundary, without replacing application logic.
  await page.addInitScript(() => {
    const original = window.setInterval;
    window.setInterval = (callback, delay, ...args) => {
      if (delay !== 1000) return original(callback, delay, ...args);
      window.runOperatorExpiryTick = () => callback(...args);
      return original(() => {
        if (!window.holdOperatorExpiryTick) callback(...args);
      }, delay);
    };
  });
  const pageErrors = [],
    scanned = [];
  page.on('pageerror', error => pageErrors.push(error.message));
  const button = name => page.getByRole('button', { name, exact: true });
  const scan = async name => {
    await page.evaluate(axe);
    const violations = await page.evaluate(async () =>
      (
        await window.axe.run({
          runOnly: { type: 'tag', values: ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'] },
        })
      ).violations.map(item => ({ id: item.id, targets: item.nodes.map(node => node.target) })),
    );
    assert.deepEqual(violations, [], name);
    scanned.push(name);
    if (screenshotDirectory) await page.screenshot({ path: join(screenshotDirectory, `${name}.png`), fullPage: true });
  };
  // The outcome notice on the page (the same words are also spoken through the live region).
  const noticed = text => page.locator('#notice').getByText(text, { exact: true }).waitFor();
  const focusedId = () => page.evaluate(() => document.activeElement?.id ?? '');
  const spoken = () => page.evaluate(() => document.getElementById('announcement').textContent);
  // A tab switch as the page sees it: the browser reports the tab visible again.
  const returnToTab = () => page.evaluate(() => document.dispatchEvent(new Event('visibilitychange')));
  const listStatuses = [];
  page.on('response', response => {
    if (new URL(response.url()).pathname === '/api/requests' && response.request().method() === 'GET')
      listStatuses.push(response.status());
  });
  const prepare = async status => {
    await page.locator('#nav-tickets').click();
    assert.equal(await page.locator('#prepare-review').isDisabled(), true, 'no status is preselected');
    await page.getByLabel('New status', { exact: true }).selectOption(status);
    await button('Prepare for review').click();
    await noticed('The change is ready for review.');
    assert.equal(await focusedId(), 'review-heading', 'focus moves to the prepared review');
  };
  const approve = async () => {
    await button('Approve…').click();
    await page.getByRole('heading', { name: 'Confirm approval', exact: true }).waitFor();
    assert.equal(await focusedId(), 'decision-heading');
    await button('Approve and submit once').focus();
    await page.keyboard.press('Enter');
  };

  await page.goto(fixture.origin);
  await button('Sign in with company account').focus();
  await page.keyboard.press('Enter');
  await page.getByText('acme', { exact: true }).waitFor();
  await page.getByRole('heading', { name: 'No requests yet', exact: true }).waitFor();
  assert.equal(new URL(page.url()).origin, fixture.origin);
  assert.equal(await page.getByText('Private ticket', { exact: true }).count(), 0);
  await scan('service-empty');
  await page.locator('#nav-setup').click();
  await page.getByText('Acme operations', { exact: true }).waitFor();
  await page.getByText(fixture.provider.issuer, { exact: true }).waitFor();
  await page.getByText(`${fixture.origin}/auth/callback`, { exact: true }).waitFor();
  const keyRow = page.getByRole('row', { name: 'Retained keys 1 4', exact: true });
  await keyRow.waitFor();
  assert.equal(
    (await page.getByRole('row', { name: /^Executor ledger / }).innerText()).includes('Not reported'),
    false,
  );
  await page
    .getByRole('row', { name: 'History segments (committed + reserved) 0 10,000 · fixed', exact: true })
    .waitFor();
  // Service checks are measured: this fixture runs without a security-event logger.
  await page
    .getByText('Both encrypted stores and their independent witnesses were read and verified for this page.')
    .waitFor();
  await page.getByText('No security-event logger is configured for this service.', { exact: true }).waitFor();
  assert.ok((await page.getByText('Needs attention', { exact: true }).count()) >= 1);
  assert.ok((await page.getByText('Ready', { exact: true }).count()) >= 2);
  await page.getByRole('heading', { name: 'Checks this page cannot make', exact: true }).waitFor();
  await page.getByText('Current-state recovery enrolled', { exact: true }).waitFor();
  await page.getByText('Enrollment checked at service startup', { exact: true }).waitFor();
  assert.equal(await page.getByText('Not verified here', { exact: true }).count(), 4);
  assert.equal(await page.locator('input').count(), 0);
  await scan('service-setup');

  await prepare('resolved');
  const first = fixture.workflow.requests('acme').requests[0];
  assert.equal(first.requesterKind, 'person');
  assert.equal(
    await page.locator('#effect-sentence').innerText(),
    'Ticket T-1 “Customer delivery” will change from open to resolved.',
  );
  await page.getByText('owner (person)', { exact: true }).waitFor();
  assert.match(await page.locator('#review-countdown').innerText(), /^expires in \d+ min \d+ s$/);
  // Deny comes first, neither decision is styled as the default, and nothing is approved by one click.
  assert.deepEqual(
    await page.locator('#decision-actions button').evaluateAll(buttons => buttons.map(item => item.id)),
    ['deny-request', 'approve-request', 'withdraw-request'],
  );
  assert.equal(await page.locator('#decision-actions .primary').count(), 0);
  assert.equal(await page.getByText(first.digest, { exact: true }).isVisible(), false, 'fingerprint is collapsed');
  await page.getByText('Technical details', { exact: true }).click();
  await page.getByText(first.digest, { exact: true }).waitFor();
  assert.equal(new URL(page.url()).hash, `#requests/${first.id}`);
  await scan('service-review');
  // An actual browser-clock expiry must remove approval while preserving held navigation.
  await page.evaluate(() => {
    window.holdOperatorExpiryTick = true;
    window.runOperatorExpiryTick();
  });
  const reviewSetupButton = await page.locator('#nav-setup').boundingBox();
  await page.mouse.move(
    reviewSetupButton.x + reviewSetupButton.width / 2,
    reviewSetupButton.y + reviewSetupButton.height / 2,
  );
  await page.mouse.down();
  await page.evaluate(expiresAt => {
    window.originalOperatorDateNow = Date.now;
    Date.now = () => expiresAt + 1;
    window.runOperatorExpiryTick();
  }, first.expiresAt);
  assert.equal(await button('Approve…').count(), 0);
  assert.equal(await page.locator('#review-countdown').count(), 0);
  await page.mouse.up();
  await page.getByRole('heading', { name: 'Setup', exact: true }).waitFor();
  assert.equal(fixture.workflow.tickets('acme').tickets[0].version, 1);
  await page.evaluate(() => {
    Date.now = window.originalOperatorDateNow;
    window.holdOperatorExpiryTick = false;
  });
  await page.locator('#nav-requests').click();
  await button('Approve…').waitFor();
  await button('Approve…').click();
  await page.getByRole('heading', { name: 'Confirm approval', exact: true }).waitFor();
  assert.equal(await focusedId(), 'decision-heading');
  // The second step repeats the effect; nothing has happened yet and Cancel returns to the review.
  assert.equal(await page.getByText('Ticket T-1 “Customer delivery” will change from open to resolved.').count(), 2);
  assert.equal(fixture.workflow.tickets('acme').tickets[0].version, 1);
  await scan('service-confirm-approval');
  await button('Cancel').click();
  assert.equal(await focusedId(), 'approve-request');
  await approve();
  await page.getByRole('region', { name: 'Confirmation record' }).waitFor();
  assert.equal(await focusedId(), 'notice', 'focus moves to the outcome');
  assert.equal(await spoken(), 'Approved. The change was applied and confirmed.');
  assert.equal(await page.getByText(/applied and confirmed/).count(), 2, 'one visible notice and the live region');
  assert.equal(
    await page.locator('#effect-sentence').innerText(),
    'Ticket T-1 “Customer delivery” was changed from open to resolved.',
  );
  assert.equal(await page.locator('#review-countdown').count(), 0, 'no review deadline on a finished request');
  assert.equal(fixture.workflow.tickets('acme').tickets[0].version, 2);
  assert.equal(fixture.workflow.requests('acme').requests[0].receipt.requestId, first.id);
  await scan('service-completed');

  await prepare('open');
  await button('Deny…').click();
  await page.getByLabel('Reason (optional)', { exact: true }).fill('Wrong ticket');
  await scan('service-deny-reason');
  await button('Deny request').click();
  await noticed('Denied. Nothing was changed.');
  assert.equal(await focusedId(), 'notice');
  await page.getByText('Wrong ticket', { exact: true }).waitFor();
  const denied = fixture.workflow.requests('acme').requests.find(request => request.state === 'denied');
  assert.equal(denied.denialReason, 'Wrong ticket');
  assert.equal(fixture.workflow.tickets('acme').tickets[0].version, 2);

  await prepare('open');
  await button('Withdraw request').click();
  await noticed('Withdrawn. Nothing was changed.');
  assert.ok(fixture.workflow.requests('acme').requests.some(request => request.state === 'withdrawn'));
  assert.equal(await button('Approve…').count(), 0);

  await prepare('open');
  loseCommitResponse = true;
  await approve();
  await button('Check whether it was applied').waitFor();
  loseCommitResponse = false;
  const unknown = fixture.workflow.requests('acme').requests.find(request => request.state === 'unconfirmed');
  assert.ok(unknown);
  assert.equal(fixture.workflow.tickets('acme').tickets[0].version, 3);
  assert.equal(await button('Approve…').count(), 0);
  await scan('service-unconfirmed');
  await button('Check whether it was applied').click();
  await page.getByRole('region', { name: 'Confirmation record' }).waitFor();
  assert.equal(fixture.workflow.tickets('acme').tickets[0].version, 3);
  assert.equal(
    fixture.workflow.requests('acme').requests.find(request => request.id === unknown.id).state,
    'completed',
  );

  // A request proposed elsewhere (here by an agent) appears without Refresh and without moving rows.
  const rowIds = () => page.locator('#request-rows .request-item').evaluateAll(rows => rows.map(row => row.id));
  const before = await rowIds();
  const proposed = (
    await fixture.workflow.propose(
      { id: 'worker-1', tenantId: 'acme', kind: 'agent', allowedTicketIds: ['T-1'] },
      { ticketId: 'T-1', status: 'resolved' },
    )
  ).request;
  await returnToTab();
  await button('1 new request · Show').waitFor();
  assert.deepEqual(await rowIds(), before, 'rows do not move under the pointer');
  assert.equal(new URL(page.url()).hash, `#requests/${unknown.id}`, 'the selection is kept');
  const served = listStatuses.length;
  await returnToTab();
  await page.waitForResponse(response => new URL(response.url()).pathname === '/api/requests');
  // WebKit answers the page from its own cache and reports 200 for the service's 304; the
  // service's 304 itself is covered by test/review.test.mjs.
  assert.ok(
    listStatuses[served] === 304 || (browserEngine === 'webkit' && listStatuses[served] === 200),
    'an unchanged poll is answered without a list',
  );
  await scan('service-new-request');
  await button('1 new request · Show').click();
  assert.equal(await focusedId(), `request-${proposed.id}`);
  assert.equal((await rowIds())[0], `request-${proposed.id}`);
  await page.locator(`#request-${proposed.id}`).click();
  await page.getByText('worker-1 (agent)', { exact: true }).waitFor();

  // Leaving and returning keeps the workspace. Only a session that really ended asks for sign-in,
  // and one click returns to the same request.
  await returnToTab();
  await page.locator('#review-heading').waitFor();
  assert.equal(await page.getByText('worker-1 (agent)', { exact: true }).count(), 1);
  fixture.app.replaceBindings(fixture.config.bindings);
  await returnToTab();
  await button('Sign in again').waitFor();
  assert.equal(await focusedId(), 'sign-in');
  assert.equal(await page.getByText('worker-1 (agent)', { exact: true }).count(), 0);
  assert.equal(new URL(page.url()).hash, `#requests/${proposed.id}`);
  await scan('service-session-ended');
  await button('Sign in again').click();
  await page.getByText('worker-1 (agent)', { exact: true }).waitFor();
  assert.equal(new URL(page.url()).hash, `#requests/${proposed.id}`);
  await button('Deny…').click();
  await button('Deny request').click();
  await noticed('Denied. Nothing was changed.');

  await page.locator('#nav-maintenance').click();
  await page.getByText('No history committed yet', { exact: true }).waitFor();
  const archiveOptions = await page.getByLabel('Finished request', { exact: true }).locator('option').allInnerTexts();
  assert.equal(new Set(archiveOptions).size, archiveOptions.length, 'archive choices are distinguishable');
  assert.ok(archiveOptions.some(label => /^Ticket T-1 · Completed · requested by owner · /.test(label)));
  await page.getByLabel('Finished request', { exact: true }).selectOption(`ticket:${first.id}`);
  await button('Preview archive').click();
  await page.getByRole('heading', { name: 'Archive preview', exact: true }).waitFor();
  assert.equal(await focusedId(), 'archive-preview-heading');
  await scan('service-archive-review');
  await button('Archive this request').click();
  await noticed('1 request archived.');
  assert.equal(await page.getByLabel('Finished request', { exact: true }).inputValue(), '');
  assert.equal(await button('Preview archive').isDisabled(), true);
  assert.equal(fixture.workflow.requests('acme').requests.find(request => request.id === first.id).archived, true);
  assert.equal(fixture.workflow.requests('acme').requests.find(request => request.id === first.id).receipt.version, 2);
  await button('Prepare activity snapshot').click();
  await page.getByRole('link', { name: 'Download activity JSON', exact: true }).waitFor();
  await scan('service-activity-snapshot');
  const downloaded = page.waitForEvent('download');
  await page.getByRole('link', { name: 'Download activity JSON', exact: true }).click();
  const activityText = await readFile(await (await downloaded).path(), 'utf8'),
    activity = JSON.parse(activityText);
  assert.equal(activity.tenantId, 'acme');
  assert.equal(activity.coverage.completeHistory, false);
  assert.ok(activity.events.some(event => event.event === 'DENIED'));
  assert.ok(activity.events.some(event => event.event === 'WITHDRAWN'));
  assert.ok(activity.events.some(event => event.event === 'TICKET_COMMITTED'));
  assert.equal(activityText.includes('Customer delivery'), false);
  assert.equal(activityText.includes('Wrong ticket'), false, 'a denial reason never enters the activity snapshot');
  assert.equal(activityText.includes(fixture.provider.clientSecret), false);
  await page.setViewportSize({ width: 375, height: 812 });
  for (const view of ['requests', 'tickets', 'maintenance', 'setup']) {
    await page.locator(`#nav-${view}`).click();
    assert.equal(await page.evaluate(() => document.documentElement.scrollWidth > innerWidth), false, view);
  }
  await scan('service-mobile-setup');
  await page.locator('#nav-maintenance').click();
  await scan('service-mobile-maintenance');
  await page.locator('#nav-requests').click();
  await page.locator(`#request-${first.id}`).click();
  await scan('service-mobile-review');
  await button('Sign out').click();
  await button('Sign in with company account').waitFor();
  const emptyFixture = await httpsSetup(
    { after: callback => cleanup.push(callback) },
    { tickets: [], server: { company: { id: 'acme', name: 'Empty company' } } },
  );
  emptyFixture.provider.controls.authorizeOverrides = { subject: 'owner' };
  await page.setViewportSize({ width: 1365, height: 950 });
  await page.goto(emptyFixture.origin);
  await button('Sign in with company account').click();
  await page.locator('#nav-tickets').click();
  await page.getByRole('heading', { name: 'No tickets enrolled yet', exact: true }).waitFor();
  await scan('service-empty-tickets');
  await button('Open setup guide').click();
  await page.getByText('Empty company', { exact: true }).waitFor();
  await page.getByText(/No company tickets are enrolled in this tenant/).waitFor();
  assert.equal(emptyFixture.workflow.tickets('acme').total, 0);
  await scan('service-empty-onboarding');
  await button('Sign out').click();
  await button('Sign in with company account').waitFor();
  const pagedFixture = await httpsSetup(
    { after: callback => cleanup.push(callback) },
    {
      limits: { maxTickets: 1000 },
      requests: { forbidSelfApproval: true },
      tickets: [
        ...Array.from({ length: 505 }, (_, index) => ({
          id: `C-${String(index).padStart(3, '0')}`,
          tenantId: 'acme',
          title: `Company record ${index}`,
          status: 'open',
        })),
        { id: 'foreign-only', tenantId: 'other', title: 'Foreign company record', status: 'open' },
      ],
      server: { company: { id: 'acme', name: 'Company with retained data' } },
    },
  );
  pagedFixture.provider.controls.authorizeOverrides = { subject: 'owner' };
  // Hold the first tick in this fresh document so the unchanged-state race is deterministic.
  await page.addInitScript(() => {
    window.holdOperatorExpiryTick = true;
  });
  await page.goto(pagedFixture.origin);
  await button('Sign in with company account').click();
  // With self-approval forbidden the requester is never offered Approve on their own request.
  await prepare('resolved');
  await page.getByText(/^You created this request, so another reviewer must approve it\./).waitFor();
  assert.equal(await button('Approve…').count(), 0);
  assert.equal(await button('Deny…').count(), 1);
  await scan('service-self-approval-forbidden');
  await button('Withdraw request').click();
  await noticed('Withdrawn. Nothing was changed.');
  assert.equal(pagedFixture.workflow.tickets('acme').tickets[0].version, 1);
  await page.locator('#nav-tickets').click();
  await page.getByText('1–500 of 505 tickets', { exact: true }).waitFor();
  await button('Next tickets').click();
  await page.getByText('501–505 of 505 tickets', { exact: true }).waitFor();
  await page.locator('#ticket-C-504').click();
  await page.getByText('C-504 · Company record 504', { exact: true }).waitFor();
  assert.equal(await page.getByText('Foreign company record', { exact: true }).count(), 0);
  await scan('service-later-ticket-page');
  const pagedSetupButton = await page.locator('#nav-setup').boundingBox();
  await page.mouse.move(
    pagedSetupButton.x + pagedSetupButton.width / 2,
    pagedSetupButton.y + pagedSetupButton.height / 2,
  );
  await page.mouse.down();
  await page.evaluate(() => window.runOperatorExpiryTick());
  await page.mouse.up();
  await page.getByRole('heading', { name: 'Setup', exact: true }).waitFor();
  await page.getByRole('row', { name: 'Tickets 506 1,000', exact: true }).waitFor();
  await button('Sign out').click();
  await button('Sign in with company account').waitFor();
  assert.equal(await page.getByText('acme', { exact: true }).count(), 0);
  pagedFixture.provider.controls.authorizeOverrides = { subject: 'not-enrolled' };
  await page.setViewportSize({ width: 1365, height: 950 });
  await button('Sign in with company account').click();
  await page.getByRole('heading', { name: 'Sign-in needs attention', exact: true }).waitFor();
  await scan('service-sign-in-failure');
  await page.setViewportSize({ width: 375, height: 812 });
  assert.equal(await page.evaluate(() => document.documentElement.scrollWidth > innerWidth), false);
  await scan('service-mobile-sign-in-failure');
  await page.getByRole('link', { name: 'Return to sign-in', exact: true }).focus();
  await page.keyboard.press('Enter');
  await button('Sign in with company account').waitFor();
  assert.deepEqual(pageErrors, []);
  // Inspect the actual encrypted stores after the browser's successful writes,
  // denial, reconciliation and archival, with the runtime owner stopped.
  fixture.close();
  const checkedStores = openMaintenance(fixture.fixture.config);
  try {
    for (const store of [checkedStores.guard, checkedStores.backend]) {
      assert.equal(store.read().schema, 3);
      assert.equal(store.recoveryMirrored(), true);
    }
  } finally {
    checkedStores.close();
  }
  const report = {
    kind: 'disposable-real-operator-service',
    node: process.version,
    browserEngine,
    browserVersion: browser.version(),
    axe: requireTools('axe-core').version,
    scanned,
    mobileViews: 6,
    oidcExchange: 'local fixture',
    storage: 'real encrypted and witnessed SQLite',
    recoveryMirrors: 'schema3 exact-current, verified after writes',
    approvals: 2,
    backendWrites: 2,
    denials: 2,
    denialReasons: 1,
    withdrawals: 2,
    receiptOnlyReconciliations: 1,
    polledNewRequests: 1,
    unchangedPollNotModified: true,
    sessionKeptAcrossTabSwitch: true,
    signInReturnsToRequest: true,
    selfApprovalNotOffered: true,
    archives: 1,
    pagedTenantTickets: 505,
    emptySeed: true,
    automaticResubmissions: 0,
    pageErrors: 0,
    unchangedExpiryTickPreservesNavigation: true,
    expiryRemovesApprovalDuringNavigation: true,
  };
  if (screenshotDirectory)
    await writeFile(join(screenshotDirectory, 'service-browser-results.json'), JSON.stringify(report, null, 2) + '\n');
  console.log(JSON.stringify(report));
} catch (error) {
  if (page && screenshotDirectory)
    await page
      .screenshot({ path: join(screenshotDirectory, 'service-check-failed.png'), fullPage: true })
      .catch(() => {});
  if (page)
    console.error(
      (
        await page
          .locator('body')
          .innerText()
          .catch(() => 'Browser document unavailable')
      ).slice(0, 3000),
    );
  throw Error(String(error.message).replace(/https?:\/\/[^\s"]+/g, '[fixture URL]'));
} finally {
  try {
    await browser?.close();
  } finally {
    for (const callback of cleanup.reverse()) await callback();
  }
}
