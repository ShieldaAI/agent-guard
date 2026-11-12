// The "Open synthetic demo" workspace. It runs the real MapService, in the page, over the
// in-memory fixture in demo-store.mjs: every answer has the service's own shape, wording and
// limits. No network is used, and the values are never presented as live inventory.
import { MapService } from '@shieldaai/agent-map/service';
import { createDemoStore } from './demo-store.mjs';

/** The demo reader sees the whole synthetic company, like an all-teams credential. */
const DEMO_SCOPE = Object.freeze({
  subject: 'demo-viewer',
  companyId: 'demo-company',
  tenantIds: ['acme-research'],
  teamIds: [],
  allTeams: true,
});
const clock = () => Date.now();
const service = new MapService(createDemoStore({ clock }), { clock });

/**
 * One demo query. A refusal rejects with the service's error, whose `code` (for example
 * `MAP_NOT_FOUND`) is what the viewer reads, as it does for a response from a real gateway.
 */
export async function queryDemo(operation, args = {}) {
  // The same plain JSON a gateway would send, so views treat demo and live responses alike.
  return JSON.parse(JSON.stringify(await service.query(DEMO_SCOPE, operation, args)));
}
