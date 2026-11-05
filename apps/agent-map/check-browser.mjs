// Run against the built viewer with disposable tooling. See this app's README.
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { createRequire } from 'node:module';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createMapToken, MapService, startMapServer } from '../../packages/agent-map/dist/index.js';

if (!process.argv[2]) throw new Error('Usage: node check-browser.mjs <browser-tools-directory>');
const requireTools = createRequire(resolve(process.argv[2], 'package.json'));
const { chromium } = requireTools('playwright');
const axe = await readFile(requireTools.resolve('axe-core/axe.min.js'), 'utf8');
const viewerDirectory = fileURLToPath(new URL('./dist', import.meta.url));
const token = createMapToken();
const scope = { subject: 'reader', companyId: 'fixture', tenantIds: ['fixture'], allTeams: true, teamIds: [] };
const agentName = 'Protected fixture agent';
const source = { id: 'fixture', tenantId: 'fixture', sourceId: 'observer', profile: 'host', previous: null,
  current: { id: 'current', snapshotId: 'snapshot', generatedAt: new Date().toISOString(), status: 'published',
    coverage: {}, edges: [], nodes: [{ id: 'node', entityId: 'agent', sourceId: 'fixture', projectionId: 'current',
      label: 'GuardAgent', properties: { name: agentName, agent_id: 'fixture-agent' } }] } };
const server = await startMapServer({ service: new MapService({ read: async () => ({ sources: [source] }) }),
  credentials: [{ token, scope }], viewerDirectory });
let browser;
try {
  browser = await chromium.launch();
  const page = await browser.newPage({ viewport: { width: 1280, height: 900 } });
  const errors = [], scans = [];
  page.on('pageerror', error => errors.push(error.message));
  const button = name => page.getByRole('button', { name, exact: typeof name === 'string' });
  const heading = name => page.getByRole('heading', { name, exact: true });
  const scan = async name => {
    const violations = await page.evaluate(async () => {
      const { violations } = await window.axe.run({ runOnly: { type: 'tag', values: ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'] } });
      return violations.map(v => ({ id: v.id, targets: v.nodes.map(n => n.target) }));
    });
    scans.push(name);
    assert.deepEqual(violations, [], name);
  };
  await page.goto(server.url);
  await page.getByLabel('Reference credential').waitFor();
  await page.evaluate(axe);
  await scan('sign-in');
  await button('Open synthetic demo').focus();
  await page.keyboard.press('Enter');
  await heading('Agent inventory').waitFor();
  await scan('inventory');
  await button(/Research assistant/).click();
  await page.getByLabel('Select a node').selectOption('resource');
  await button('Explain').click();
  await page.getByText('Execution remains unknown').waitFor();
  assert.equal(await heading('IAM policy evidence').count(), 1);
  await scan('agent explanation');
  await page.getByLabel('Resource selector').fill('out-of-scope');
  assert.equal(await page.getByText('Execution remains unknown').isVisible(), false);
  await button('Explain').click();
  await page.getByText('Observed blocker').waitFor();
  await scan('observed blocker');
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
  await page.getByText('research-followup').waitFor();
  await scan('snapshot comparison');
  await button('Health').click();
  await button('Refresh evidence').click();
  await heading('Collection health').waitFor();
  await scan('collection health');
  await page.setViewportSize({ width: 375, height: 812 });
  await scan('mobile health');
  for (const tab of ['Agent inventory', 'Potential access', 'Changes', 'Health']) {
    const bounds = await button(tab).boundingBox();
    assert.ok(bounds.x >= 0 && bounds.x + bounds.width <= 375, `${tab} navigation fits the viewport`);
    await button(tab).click();
    assert.equal(await page.evaluate(() => document.documentElement.scrollWidth > innerWidth), false, tab);
  }
  await button('Disconnect').click();
  await page.getByLabel('Reference credential').fill(token);
  await button('Open agent map').click();
  await button(new RegExp(agentName)).waitFor();
  let resumeListing;
  const listingPaused = new Promise(resolve => { resumeListing = resolve; });
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
  assert.deepEqual(errors, []);
  console.log(JSON.stringify({ chromium: browser.version(), axe: await page.evaluate(() => window.axe.version),
    scanned: scans, mobileViews: 4, failedFilterHidesStaleResults: true, inventoryRetrySucceeded: true, bearerDenialClearedEvidence: true }));
} finally {
  try { await browser?.close(); } finally { await server.close(); }
}
