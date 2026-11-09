// Run against the built viewer with disposable tooling. See this app's README.
import assert from 'node:assert/strict';
import { readFile, mkdir, writeFile } from 'node:fs/promises';
import { createRequire } from 'node:module';
import { resolve, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createMapToken, MapService, startMapServer } from '../../packages/agent-map/dist/index.js';
import { startMapIdentityServer } from '../../packages/agent-map/dist/identity-http.js';
import { createTestIdentityProvider } from '../../packages/agent-map/test/helpers/oidc-provider.mjs';
import { inventoryBrowserFixture } from './test/inventory-fixture.mjs';

if (!process.argv[2])
  throw new Error(
    'Usage: node check-browser.mjs <browser-tools-directory> [screenshot-directory] [chromium|firefox|webkit]',
  );
const requireTools = createRequire(resolve(process.argv[2], 'package.json'));
const browserEngine = process.argv[4] ?? 'chromium';
if (!['chromium', 'firefox', 'webkit'].includes(browserEngine)) throw new Error('Unsupported browser engine');
const browserType = requireTools('playwright')[browserEngine];
const screenshotDirectory = process.argv[3] ? resolve(process.argv[3]) : null;
if (screenshotDirectory) await mkdir(screenshotDirectory, { recursive: true, mode: 0o700 });
const axe = await readFile(requireTools.resolve('axe-core/axe.min.js'), 'utf8');
const viewerDirectory = fileURLToPath(new URL('./dist', import.meta.url));
const token = createMapToken();
const scope = { subject: 'reader', companyId: 'fixture', tenantIds: ['fixture'], allTeams: true, teamIds: [] };
const agentName = 'Catalog assistant';
const source = inventoryBrowserFixture();
let activeReads = 0,
  peakReads = 0;
const read = async () => {
  activeReads++;
  peakReads = Math.max(peakReads, activeReads);
  try {
    await new Promise(resolve => setTimeout(resolve, 100));
    return { sources: [source] };
  } finally {
    activeReads--;
  }
};
const server = await startMapServer({
  service: new MapService({ read }),
  credentials: [{ token, scope }],
  viewerDirectory,
});
let browser, page;
const cleanup = [];
try {
  browser = await browserType.launch();
  page = await browser.newPage({ ignoreHTTPSErrors: true, locale: 'en-US', viewport: { width: 1280, height: 900 } });
  page.setDefaultTimeout(12_000);
  const errors = [],
    scans = [];
  page.on('pageerror', error => errors.push(error.message));
  const button = name => page.getByRole('button', { name, exact: typeof name === 'string' });
  const heading = name => page.getByRole('heading', { name, exact: true });
  const scan = async name => {
    const violations = await page.evaluate(async () => {
      const { violations } = await window.axe.run({
        runOnly: { type: 'tag', values: ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'] },
      });
      return violations.map(v => ({ id: v.id, targets: v.nodes.map(n => n.target) }));
    });
    scans.push(name);
    assert.deepEqual(violations, [], name);
    if (screenshotDirectory)
      await page.screenshot({ path: join(screenshotDirectory, `${name.replaceAll(' ', '-')}.png`), fullPage: true });
  };
  await page.goto(server.url);
  await page.getByLabel('Reference credential').waitFor();
  await page.evaluate(axe);
  await scan('sign-in');
  await button('Open synthetic demo').focus();
  await page.keyboard.press('Enter');
  await heading('Agent inventory').waitFor();
  await button(/Research assistant/).waitFor();
  await scan('inventory');
  await button(/Research assistant/).click();
  await button('Show graph').click();
  await page.getByLabel('Select a node').selectOption('resource');
  const graphGeometry = await page.locator('.graph').evaluate(container => {
    const cy = container._cyreg.cy;
    const boxes = cy.nodes().map(node => node.renderedBoundingBox({ includeLabels: true, includeOverlays: false }));
    let overlappingNodeLabels = 0;
    for (let i = 0; i < boxes.length; i++)
      for (let j = i + 1; j < boxes.length; j++) {
        const a = boxes[i],
          b = boxes[j];
        if (Math.min(a.x2, b.x2) > Math.max(a.x1, b.x1) && Math.min(a.y2, b.y2) > Math.max(a.y1, b.y1))
          overlappingNodeLabels++;
      }
    return {
      viewportWidth: container.clientWidth,
      minimumRenderedNodeFont: Math.min(
        ...cy.nodes().map(node => Number(node.style('font-size').replace('px', '')) * cy.zoom()),
      ),
      overlappingNodeLabels,
    };
  });
  assert.equal(graphGeometry.overlappingNodeLabels, 0, 'default graph fit must keep node labels separate');
  assert.ok(
    graphGeometry.minimumRenderedNodeFont >= 8,
    `default graph text too small: ${JSON.stringify(graphGeometry)}`,
  );
  await scan('agent relationship graph');
  await button('Permissions').click();
  await button('Explain').click();
  await page.getByText('Execution remains unknown').waitFor();
  assert.equal(await heading('IAM policy evidence').count(), 1);
  await scan('agent explanation');
  await page.getByLabel('Resource selector').fill('out-of-scope');
  assert.equal(await page.getByText('Execution remains unknown').isVisible(), false);
  await button('Explain').click();
  await page.getByText('Observed blocker').waitFor();
  await scan('observed blocker');
  await button('Resources').click();
  await button('Potential access').click();
  await page.getByLabel('Resource reference').fill('arn:aws:s3:::company-reports/quarterly/summary.pdf');
  await button('Find candidates').click();
  await button(/Research assistant/).waitFor();
  await scan('matching resource');
  await page.getByLabel('Action', { exact: true }).fill('s3:DeleteObject');
  assert.equal(await button(/Research assistant/).isVisible(), false);
  await button('Find candidates').click();
  await heading('No matching candidates').waitFor();
  await scan('unmatched resource');
  await button('Changes').click();
  await button('Compare snapshots').click();
  await page.getByText('research-followup', { exact: true }).first().waitFor();
  await scan('snapshot comparison');
  await button('Health').click();
  await button('Refresh evidence').click();
  await heading('Collection health').waitFor();
  await scan('collection health');
  await page.setViewportSize({ width: 375, height: 812 });
  await scan('mobile health');
  for (const tab of ['Agent inventory', 'Owners', 'Resources', 'Changes', 'Health']) {
    const bounds = await button(tab).boundingBox();
    assert.ok(bounds.x >= 0 && bounds.x + bounds.width <= 375, `${tab} navigation fits the viewport`);
    await button(tab).click();
    if (tab === 'Changes') {
      await page.getByText('Selected source details', { exact: true }).focus();
      await page.keyboard.press('Enter');
      await scan('mobile snapshot source');
    }
    assert.equal(await page.evaluate(() => document.documentElement.scrollWidth > innerWidth), false, tab);
  }
  await button('Disconnect').click();
  await page.getByLabel('Reference credential').fill(token);
  await button('Open agent map').click();
  await button(new RegExp(agentName)).waitFor();
  await page.setViewportSize({ width: 1280, height: 900 });
  await button('Next agents page').click();
  await page.getByText('21–25 of 25', { exact: true }).waitFor();
  await button('Previous agents page').click();
  await button(new RegExp(agentName)).click();
  await heading('Agent overview').waitFor();
  await page.getByText('Company registry', { exact: true }).waitFor();
  assert.equal(
    await page
      .locator('.inventory-properties > div')
      .filter({ has: page.getByText('Manifest revision', { exact: true }) })
      .locator('dd')
      .innerText(),
    '4',
  );
  await scan('v2 agent overview');
  await button('Permissions').click();
  await page.getByRole('table', { name: 'Declared permissions', exact: true }).waitFor();
  await page.getByText(/Approval events, request-time decisions, backend receipts/).waitFor();
  await scan('v2 declared permissions');
  await button('Connections & resources').click();
  await page.getByRole('table', { name: 'Credential references', exact: true }).waitFor();
  await page
    .getByRole('table', { name: 'Credential references', exact: true })
    .getByText('Company service reference', { exact: true })
    .waitFor();
  await page.getByRole('columnheader', { name: 'Expiry at capture', exact: true }).waitFor();
  const resourceBinding = page
    .getByRole('table', { name: 'Tool and resource bindings', exact: true })
    .getByRole('row')
    .filter({ hasText: 'records-0' });
  await resourceBinding.getByText('Resource binding', { exact: true }).waitFor();
  await resourceBinding.getByText('Not applicable', { exact: true }).waitFor();
  await page
    .getByRole('table', { name: 'Relationships', exact: true })
    .getByText('Accountable platform team', { exact: true })
    .first()
    .waitFor();
  await scan('v2 connections and credential references');
  await page
    .getByRole('table', { name: 'Connected resources', exact: true })
    .getByRole('button', { name: 'Company records', exact: true })
    .focus();
  await page.keyboard.press('Enter');
  await heading('Company records').waitFor();
  await page.getByRole('table', { name: 'Dependencies', exact: true }).waitFor();
  await button(agentName).click();
  await button('Agent changes').click();
  await button('Compare snapshots').click();
  await page.getByRole('columnheader', { name: 'Before', exact: true }).first().waitFor();
  await page.getByRole('columnheader', { name: 'After', exact: true }).first().waitFor();
  await scan('v2 ownership and permission changes');
  await button('Changes').click();
  await button('Compare snapshots').click();
  await button('Next changes page').click();
  await page.getByText('21–26 of 26', { exact: true }).waitFor();
  await button('Owners').click();
  await page.getByText('Accountable platform team', { exact: true }).waitFor();
  await scan('v2 owner directory');
  await button('Next owners page').click();
  await page.getByText('21–23 of 23', { exact: true }).waitFor();
  await button('Previous owners page').click();
  const ownerRow = page.getByRole('row').filter({ hasText: 'Accountable platform team' });
  await ownerRow.getByRole('button', { name: 'View 1 agents', exact: true }).click();
  await button(new RegExp(agentName)).waitFor();
  assert.equal(await page.getByLabel('Filter by owner ID').inputValue(), 'owner-0');
  await button('Clear owner filter').click();
  await button('Resources').click();
  await button('Next resources page').click();
  await page.getByText('21–25 of 25', { exact: true }).waitFor();
  await button('Previous resources page').click();
  await button('Company records').click();
  await heading('Company records').waitFor();
  await page.getByRole('table', { name: 'Resource targets', exact: true }).waitFor();
  await scan('v2 resource relationships');
  await button(agentName).click();
  await heading('Agent overview').waitFor();
  await page.getByLabel('Search visible agents').fill('Large catalog agent');
  await button(/Large catalog agent/).click();
  await heading('Agent overview').waitFor();
  await button('Show graph').click();
  await page
    .getByText('This neighborhood exceeds the graph display limit. All paged inventory sections remain available.', {
      exact: true,
    })
    .waitFor();
  await page.getByRole('table', { name: 'Tasks', exact: true }).waitFor();
  await button('Next tasks page').click();
  await page.getByText('21–40 of 511', { exact: true }).waitFor();
  await scan('v2 large agent paged detail');
  await page.getByLabel('Search visible agents').fill('Directory agent 03');
  await button(/Directory agent 03/).click();
  await page
    .getByText('Legacy metadata does not establish ownership or lifecycle state. Missing fields remain unknown.', {
      exact: true,
    })
    .waitFor();
  await page.getByText('legacy-reported-owner', { exact: true }).waitFor();
  assert.equal(
    await page
      .locator('.inventory-properties')
      .filter({ hasText: 'Ownership status' })
      .getByText('Ownership unknown', { exact: true })
      .count(),
    1,
  );
  await scan('legacy unknown ownership');
  await page.getByLabel('Search visible agents').fill('');
  await page.getByLabel('Ownership status').selectOption('unassigned');
  await button(/Directory agent 02/).waitFor();
  assert.equal(await button(/Directory agent 03/).count(), 0);
  await page.getByLabel('Ownership status').selectOption('');
  await page.setViewportSize({ width: 375, height: 812 });
  await button('Owners').click();
  await page.getByRole('table', { name: 'Visible owners', exact: true }).waitFor();
  await page
    .getByText('Scroll horizontally for more columns. Keyboard users can focus the table and use arrow keys.', {
      exact: true,
    })
    .waitFor();
  await scan('mobile owner directory');
  assert.equal(await page.evaluate(() => document.documentElement.scrollWidth > innerWidth), false);
  await button('Resources').click();
  await button('Company records').click();
  await heading('Company records').waitFor();
  await scan('mobile resource detail');
  assert.equal(await page.evaluate(() => document.documentElement.scrollWidth > innerWidth), false);
  await button('Agent inventory').click();
  await button(new RegExp(agentName)).click();
  await button('Agent changes').click();
  await button('Compare snapshots').click();
  await page.getByRole('columnheader', { name: 'Before', exact: true }).first().waitFor();
  await scan('mobile permission changes');
  assert.equal(await page.evaluate(() => document.documentElement.scrollWidth > innerWidth), false);
  await button('Agent inventory').click();
  let resumeListing;
  const listingPaused = new Promise(resolve => {
    resumeListing = resolve;
  });
  await page.route('**/v1/query', async route => {
    await listingPaused;
    await route.fulfill({ status: 503, body: 'service unavailable' });
  });
  await page.getByLabel('Search visible agents').fill('unmatched-filter');
  await page.getByText('Loading agents…', { exact: true }).waitFor();
  assert.equal(await button(new RegExp(agentName)).count(), 0);
  resumeListing();
  await page.getByText('Inventory could not be loaded. Select Refresh evidence to retry.', { exact: true }).waitFor();
  assert.equal(await button(new RegExp(agentName)).count(), 0);
  await heading('Refresh inventory to continue').waitFor();
  assert.equal(await heading('Choose an agent to explore').count(), 0);
  await scan('inventory unavailable');
  await page.unroute('**/v1/query');
  await page.getByLabel('Search visible agents').fill('');
  await button('Refresh evidence').click();
  await button(new RegExp(agentName)).waitFor();
  await page.route('**/v1/query', route => route.fulfill({ status: 401, body: 'invalid credential' }));
  await button('Refresh evidence').click();
  await page.getByRole('alert').waitFor();
  assert.equal(await page.getByLabel('Reference credential').isVisible(), true);
  assert.equal(await page.getByText(agentName, { exact: true }).count(), 0);
  await page.unroute('**/v1/query');
  const provider = await createTestIdentityProvider({ after: callback => cleanup.push(callback) });
  provider.controls.authorizeOverrides = { subject: 'company-reader' };
  const gateway = await startMapIdentityServer({
    service: new MapService({ read }),
    publicOrigin: 'https://127.0.0.1:0',
    port: 0,
    listenHost: '127.0.0.1',
    viewerDirectory,
    companyId: 'fixture',
    bindings: [{ subject: 'company-reader', scope }],
    tls: { cert: provider.cert, key: provider.key },
    oidc: {
      issuer: provider.issuer,
      clientId: provider.clientId,
      clientSecret: provider.clientSecret,
      ca: provider.ca,
    },
  });
  cleanup.push(() => gateway.close());
  await page.setViewportSize({ width: 1280, height: 900 });
  await page.goto(gateway.url);
  await button('Sign in with company account').focus();
  await page.keyboard.press('Enter');
  await button(new RegExp(agentName)).waitFor();
  await page.getByText('Company session', { exact: true }).waitFor();
  await page.evaluate(axe);
  await scan('company signed in');
  const companyQueryUrl = new URL('/v1/query', gateway.url).href;
  let refreshRequest;
  // Revoke after the user's click starts its health request. Revoking first can
  // correctly clear the workspace through a pending background listing before
  // Playwright has clicked the now-removed refresh control.
  const revokeOnRefresh = async route => {
    if (!refreshRequest && route.request().postDataJSON()?.operation === 'get_inventory_health') {
      refreshRequest = route.request();
      gateway.invalidateSessions();
    }
    await route.continue();
  };
  await page.route(companyQueryUrl, revokeOnRefresh);
  try {
    // Any first real 401 may close the session and cancel its peer requests.
    // Require refresh to trigger revocation, without requiring health to win.
    const [deniedRefresh] = await Promise.all([
      page.waitForResponse(
        response => Boolean(refreshRequest) && response.url() === companyQueryUrl && response.status() === 401,
      ),
      button('Refresh evidence').click(),
    ]);
    assert.ok(refreshRequest, 'the clicked refresh health request triggered gateway revocation');
    assert.equal(deniedRefresh.status(), 401, 'refresh-triggered revocation reaches the real gateway');
  } finally {
    await page.unroute(companyQueryUrl, revokeOnRefresh);
  }
  await button('Check sign-in').waitFor();
  assert.equal(await page.getByText(agentName, { exact: true }).count(), 0);
  await scan('company session revoked');
  await button('Check sign-in').focus();
  await page.keyboard.press('Enter');
  await button('Sign in with company account').waitFor();
  await button('Sign in with company account').click();
  await button(new RegExp(agentName)).waitFor();
  // Also require revocation from an automatic filter read, with no subsequent
  // refresh click. Hold that exact request so the race is deterministic.
  let releaseBackground;
  const backgroundHeld = new Promise(resolve => {
    releaseBackground = resolve;
  });
  const pendingSearch = 'pending-company-revocation';
  const isBackground = request =>
    request.url() === companyQueryUrl &&
    request.postDataJSON()?.operation === 'list_agents' &&
    request.postDataJSON()?.args?.search === pendingSearch;
  const holdBackground = async route => {
    if (isBackground(route.request())) await backgroundHeld;
    await route.continue();
  };
  await page.route(companyQueryUrl, holdBackground);
  try {
    const [request] = await Promise.all([
      page.waitForRequest(isBackground),
      page.getByLabel('Search visible agents').fill(pendingSearch),
    ]);
    const deniedBackground = page.waitForResponse(response => response.request() === request);
    gateway.invalidateSessions();
    releaseBackground();
    assert.equal((await deniedBackground).status(), 401, 'background read reaches the real revoked gateway');
    await button('Check sign-in').waitFor();
    assert.equal(await button('Refresh evidence').count(), 0);
    assert.equal(await page.getByText(agentName, { exact: true }).count(), 0);
  } finally {
    releaseBackground();
    await page.unroute(companyQueryUrl, holdBackground);
  }
  await button('Check sign-in').click();
  await button('Sign in with company account').click();
  await button(new RegExp(agentName)).waitFor();
  await button('Sign out').click();
  await button('Sign in with company account').waitFor();
  assert.equal(await page.getByText(agentName, { exact: true }).count(), 0);
  await page.evaluate(axe);
  await scan('company signed out');
  assert.deepEqual(errors, []);
  assert.ok(peakReads <= 2, `workspace reads exceed the two-slot query queue: ${peakReads}`);
  const report = {
    kind: 'synthetic-inventory-real-map-gateways',
    browserEngine,
    browserVersion: browser.version(),
    axe: await page.evaluate(() => window.axe.version),
    scanned: scans,
    mobileViews: 8,
    graphGeometry,
    queryQueue: { simulatedReadDelayMs: 100, peakReads, maximum: 2 },
    inventoryV2: {
      owners: true,
      resources: true,
      exactChanges: true,
      pagedIndexes: true,
      largeGraphDoesNotBlockDetail: true,
      credentialReferencesOnly: true,
      legacyUnknownOwnership: true,
    },
    failedFilterHidesStaleResults: true,
    inventoryRetrySucceeded: true,
    bearerDenialClearedEvidence: true,
    oidcExchange: 'local signed fixture',
    companyRevocationClearedEvidence: true,
    refreshTriggeredRevocationReturned401: true,
    backgroundRevocationReturned401: true,
    backgroundRevocationClearedWithoutRefresh: true,
    companySignoutClearedEvidence: true,
  };
  if (screenshotDirectory)
    await writeFile(join(screenshotDirectory, 'map-browser-results.json'), JSON.stringify(report, null, 2) + '\n');
  console.log(JSON.stringify(report));
} catch (error) {
  if (page && screenshotDirectory)
    await page.screenshot({ path: join(screenshotDirectory, 'map-check-failed.png'), fullPage: true }).catch(() => {});
  if (page) {
    console.error(
      (
        await page
          .locator('body')
          .innerText()
          .catch(() => 'Document unavailable')
      ).slice(0, 3000),
    );
    console.error(
      JSON.stringify(
        await page
          .evaluate(() => ({
            viewport: innerWidth,
            width: document.documentElement.scrollWidth,
            overflow: [...document.querySelectorAll('body *')]
              .filter(
                element =>
                  element.getBoundingClientRect().right > innerWidth + 1 ||
                  element.scrollWidth > element.clientWidth + 1,
              )
              .map(element => ({
                tag: element.tagName,
                class: element.className,
                label: element.getAttribute('aria-label'),
                right: element.getBoundingClientRect().right,
                width: element.clientWidth,
                scroll: element.scrollWidth,
              }))
              .slice(0, 25),
          }))
          .catch(() => ({})),
      ),
    );
  }
  throw Error(String(error.message).replace(/https?:\/\/[^\s"]+/g, '[fixture URL]'));
} finally {
  try {
    await browser?.close();
  } finally {
    for (const callback of cleanup.reverse()) await callback();
    await server.close();
  }
}
