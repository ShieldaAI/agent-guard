// Read the owned disposable test database; input/output carry no database credentials.
import { readFileSync } from 'node:fs';
import { createNeo4jMapStore } from '../../../../packages/agent-map/dist/store.js';
import { MapService } from '../../../../packages/agent-map/dist/service.js';

const configuration = JSON.parse(readFileSync(process.env.AGENT_GUARD_TEST_NEO4J_CONFIG, 'utf8'));
const input = JSON.parse(readFileSync(0, 'utf8'));
const store = createNeo4jMapStore({ uri: configuration.uri, username: configuration.username,
  password: configuration.password, ...input.limits,
  ...(Number.isSafeInteger(input.now) ? { clock: () => input.now } : {}) });
try {
  const view = await store.read(input.scope, input.request ?? {});
  const service = new MapService(store, { clock: () => input.now ?? 1793350800000 });
  const outputs = [];
  for (const { operation, args } of input.operations ?? []) {
    try { outputs.push({ ok: true, response: await service.query(input.scope, operation, args) }); }
    catch (error) { outputs.push({ ok: false, code: error.code ?? 'MAP_UNAVAILABLE' }); }
  }
  process.stdout.write(JSON.stringify({ ok: true, view, outputs }));
} catch (error) {
  process.stdout.write(JSON.stringify({ ok: false, code: error.code ?? 'MAP_UNAVAILABLE' }));
} finally { await store.close(); }
