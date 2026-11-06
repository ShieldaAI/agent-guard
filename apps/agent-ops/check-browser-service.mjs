// Real disposable HTTPS service, encrypted stores, OIDC exchange and browser UI.
// Only the identity provider and the post-commit failure are local test fixtures.
import assert from 'node:assert/strict';
import { readFile, mkdir, writeFile } from 'node:fs/promises';
import { createRequire } from 'node:module';
import { join, resolve } from 'node:path';
import { httpsSetup } from './test/helpers.mjs';
import { openMaintenance } from './runtime.mjs';

if (!process.argv[2]) throw new Error('Usage: node apps/agent-ops/check-browser-service.mjs <browser-tools-directory> [screenshot-directory] [chromium|firefox|webkit]');
const requireTools = createRequire(resolve(process.argv[2], 'package.json'));
const browserEngine = process.argv[4] ?? 'chromium';
if (!['chromium', 'firefox', 'webkit'].includes(browserEngine)) throw new Error('Unsupported browser engine');
const browserType = requireTools('playwright')[browserEngine];
const axe = await readFile(requireTools.resolve('axe-core/axe.min.js'), 'utf8');
const screenshotDirectory = process.argv[3] ? resolve(process.argv[3]) : null;
if (screenshotDirectory) await mkdir(screenshotDirectory, { recursive: true, mode: 0o700 });
const cleanup = [];
let browser, page, loseCommitResponse = false;
try {
  const fixture = await httpsSetup({ after: callback => cleanup.push(callback) }, {
    afterCommit: () => { if (loseCommitResponse) throw new Error('Synthetic response loss after durable commit'); },
    server: { company: { id: 'acme', name: 'Acme operations' } },
  });
  fixture.provider.controls.authorizeOverrides = { subject: 'owner' };
  browser = await browserType.launch();
  // Browser-only exception for the disposable self-signed fixture certificate.
  // The service OIDC client still verifies its configured local CA.
  page = await browser.newPage({ ignoreHTTPSErrors: true, locale: 'en-US', viewport: { width: 1365, height: 950 } });
  page.setDefaultTimeout(12_000);
  const pageErrors = [], scanned = [];
  page.on('pageerror', error => pageErrors.push(error.message));
  const button = name => page.getByRole('button', { name, exact: true });
  const scan = async name => {
    await page.evaluate(axe);
    const violations = await page.evaluate(async () => (await window.axe.run({
      runOnly: { type: 'tag', values: ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'] },
    })).violations.map(item => ({ id: item.id, targets: item.nodes.map(node => node.target) })));
    assert.deepEqual(violations, [], name);
    scanned.push(name);
    if (screenshotDirectory) await page.screenshot({ path: join(screenshotDirectory, `${name}.png`), fullPage: true });
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
  assert.equal((await page.getByRole('row', { name: /^Executor ledger / }).innerText()).includes('Not reported'), false);
  await page.getByRole('heading', { name: 'Company acceptance checks', exact: true }).waitFor();
  await page.getByText('Current-state recovery enrolled', { exact: true }).waitFor();
  await page.getByText('Enrollment checked at service startup', { exact: true }).waitFor();
  assert.equal(await page.getByText('Not verified here', { exact: true }).count(), 4);
  assert.equal(await page.locator('input').count(), 0);
  await scan('service-setup');

  await page.locator('#nav-tickets').click();
  await button('Prepare review').click();
  await button('Approve and submit once').waitFor();
  const first = fixture.workflow.requests('acme').requests[0];
  await page.getByText(first.digest, { exact: true }).waitFor();
  await scan('service-review');
  await button('Approve and submit once').focus();
  await page.keyboard.press('Enter');
  await page.getByRole('region', { name: 'Backend receipt' }).waitFor();
  assert.equal(fixture.workflow.tickets('acme').tickets[0].version, 2);
  assert.equal(fixture.workflow.requests('acme').requests[0].receipt.requestId, first.id);
  await scan('service-completed');

  await page.locator('#nav-tickets').click();
  await page.getByLabel('Requested status', { exact: true }).selectOption('open');
  await button('Prepare review').click();
  await button('Deny request').click();
  await page.getByText('The reviewer denied this prepared change.', { exact: true }).waitFor();
  assert.equal(fixture.workflow.tickets('acme').tickets[0].version, 2);

  await page.locator('#nav-tickets').click();
  await button('Prepare review').click();
  loseCommitResponse = true;
  await button('Approve and submit once').click();
  await button('Check backend receipt').waitFor();
  const unknown = fixture.workflow.requests('acme').requests.find(request => request.state === 'unconfirmed');
  assert.ok(unknown);
  assert.equal(fixture.workflow.tickets('acme').tickets[0].version, 3);
  assert.equal(await button('Approve and submit once').count(), 0);
  await scan('service-unconfirmed');
  await button('Check backend receipt').click();
  await page.getByRole('region', { name: 'Backend receipt' }).waitFor();
  assert.equal(fixture.workflow.tickets('acme').tickets[0].version, 3);
  assert.equal(fixture.workflow.requests('acme').requests.find(request => request.id === unknown.id).state, 'completed');

  await page.locator('#nav-maintenance').click();
  await button('Refresh').click();
  await page.getByText('No history committed yet', { exact: true }).waitFor();
  await page.getByLabel('Task', { exact: true }).selectOption(`ticket:${first.id}`);
  await button('Preview archive').click();
  await button('Archive 1 eligible task').waitFor();
  await scan('service-archive-review');
  await button('Archive 1 eligible task').click();
  await page.getByText('1 task archived.', { exact: true }).waitFor();
  assert.equal(await page.getByLabel('Task', { exact: true }).inputValue(), '');
  assert.equal(await page.getByLabel('Task', { exact: true }).locator('option:checked').textContent(), 'Choose a task');
  assert.equal(await button('Preview archive').isDisabled(), true);
  assert.equal(fixture.workflow.requests('acme').requests.find(request => request.id === first.id).archived, true);
  assert.equal(fixture.workflow.requests('acme').requests.find(request => request.id === first.id).receipt.version, 2);
  await button('Prepare activity snapshot').click();
  await page.getByRole('link', { name: 'Download activity JSON', exact: true }).waitFor();
  await scan('service-activity-snapshot');
  const downloaded = page.waitForEvent('download');
  await page.getByRole('link', { name: 'Download activity JSON', exact: true }).click();
  const activityText = await readFile(await (await downloaded).path(), 'utf8'), activity = JSON.parse(activityText);
  assert.equal(activity.tenantId, 'acme'); assert.equal(activity.coverage.completeHistory, false);
  assert.ok(activity.events.some(event => event.event === 'DENIED'));
  assert.ok(activity.events.some(event => event.event === 'TICKET_COMMITTED'));
  assert.equal(activityText.includes('Customer delivery'), false);
  assert.equal(activityText.includes(fixture.provider.clientSecret), false);
  await page.setViewportSize({ width: 375, height: 812 });
  for (const view of ['requests', 'tickets', 'maintenance', 'setup']) {
    await page.locator(`#nav-${view}`).click();
    assert.equal(await page.evaluate(() => document.documentElement.scrollWidth > innerWidth), false, view);
  }
  await scan('service-mobile-setup');
  await page.locator('#nav-maintenance').click();
  await scan('service-mobile-maintenance');
  await button('Sign out').click();
  await button('Sign in with company account').waitFor();
  const emptyFixture = await httpsSetup({ after: callback => cleanup.push(callback) }, { tickets: [],
    server: { company: { id: 'acme', name: 'Empty company' } } });
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
  const pagedFixture = await httpsSetup({ after: callback => cleanup.push(callback) }, {
    limits: { maxTickets: 1000 }, tickets: [...Array.from({ length: 505 }, (_, index) => ({
      id: `C-${String(index).padStart(3, '0')}`, tenantId: 'acme', title: `Company record ${index}`, status: 'open',
    })), { id: 'foreign-only', tenantId: 'other', title: 'Foreign company record', status: 'open' }],
    server: { company: { id: 'acme', name: 'Company with retained data' } },
  });
  pagedFixture.provider.controls.authorizeOverrides = { subject: 'owner' };
  await page.goto(pagedFixture.origin);
  await button('Sign in with company account').click();
  await page.locator('#nav-tickets').click();
  await page.getByText('1–500 of 505 tickets', { exact: true }).waitFor();
  await button('Next tickets').click();
  await page.getByText('501–505 of 505 tickets', { exact: true }).waitFor();
  await page.locator('#ticket-C-504').click();
  await page.getByText('Company record 504', { exact: true }).last().waitFor();
  assert.equal(await page.getByText('Foreign company record', { exact: true }).count(), 0);
  await scan('service-later-ticket-page');
  await page.locator('#nav-setup').click();
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
  } finally { checkedStores.close(); }
  const report = { kind: 'disposable-real-operator-service', node: process.version, browserEngine, browserVersion: browser.version(),
    axe: requireTools('axe-core').version, scanned, mobileViews: 5, oidcExchange: 'local fixture',
    storage: 'real encrypted and witnessed SQLite', recoveryMirrors: 'schema3 exact-current, verified after writes', approvals: 2, backendWrites: 2, denials: 1,
    receiptOnlyReconciliations: 1, archives: 1, pagedTenantTickets: 505, emptySeed: true, automaticResubmissions: 0, pageErrors: 0 };
  if (screenshotDirectory) await writeFile(join(screenshotDirectory, 'service-browser-results.json'), JSON.stringify(report, null, 2) + '\n');
  console.log(JSON.stringify(report));
} catch (error) {
  if (page && screenshotDirectory) await page.screenshot({ path: join(screenshotDirectory, 'service-check-failed.png'), fullPage: true }).catch(() => {});
  if (page) console.error((await page.locator('body').innerText().catch(() => 'Browser document unavailable')).slice(0, 3000));
  throw Error(String(error.message).replace(/https?:\/\/[^\s"]+/g, '[fixture URL]'));
} finally {
  try { await browser?.close(); }
  finally { for (const callback of cleanup.reverse()) await callback(); }
}
