#!/usr/bin/env node
import { resolve } from 'node:path';
import { parseArgs } from 'node:util';
import { PACKAGE_VERSION, STORE_LIMITS, isCliEntry, reportStartupFailure } from './cli-entry.js';
import { createNeo4jMapStore } from './store.js';
import { MapService } from './service.js';
import { startMapServer, type MapCredential } from './http.js';
import { validateReadScope } from './types.js';
import { fail, integer } from './common.js';
import { fields, parseRequest, readHostFile } from './boundary.js';

function environmentName(value: unknown): string {
  if (typeof value !== 'string' || !/^[A-Za-z_][A-Za-z0-9_]{0,127}$/.test(value)) fail('MAP_CONFIG_INVALID');
  return value;
}
/** The reference launcher's configuration: a regular file of this user or root, not writable by others. */
const CONFIG_FILE = { noFollow: false, owner: 'service-or-root', singleLink: false, private: false } as const;
const USAGE = 'agent-guard-map --config HOST_CONFIG.json | --help | --version';
/** Credential values stay in the environment and are never printed by this launcher. */
export async function runMapCli(argv: string[] = process.argv.slice(2)): Promise<void> {
  const { values } = parseArgs({
    args: argv,
    options: { config: { type: 'string' }, help: { type: 'boolean' }, version: { type: 'boolean' } },
    strict: true,
  });
  if (values.help) {
    process.stdout.write(`${USAGE}\n`);
    return;
  }
  if (values.version) {
    process.stdout.write(`${PACKAGE_VERSION}\n`);
    return;
  }
  if (!values.config) fail('MAP_ARGUMENT_INVALID');
  const path = resolve(values.config);
  const config = fields(
    parseRequest(await readHostFile(path, 128 * 1024, CONFIG_FILE), 128 * 1024),
    ['neo4j', 'credentials', 'port', 'viewerDirectory'],
    ['neo4j', 'credentials'],
  );
  const database = fields(
    config.neo4j,
    ['uri', 'username', 'passwordEnv', 'database', ...STORE_LIMITS],
    ['uri', 'username', 'passwordEnv'],
  );
  if (
    typeof database.uri !== 'string' ||
    typeof database.username !== 'string' ||
    (database.database !== undefined && typeof database.database !== 'string')
  )
    fail('MAP_CONFIG_INVALID');
  const password = process.env[environmentName(database.passwordEnv)];
  if (!password) fail('MAP_CREDENTIAL_REQUIRED');
  if (!Array.isArray(config.credentials) || config.credentials.length < 1 || config.credentials.length > 128)
    fail('MAP_CONFIG_INVALID');
  const credentials: MapCredential[] = config.credentials.map(value => {
    const entry = fields(value, ['tokenEnv', 'scope'], ['tokenEnv', 'scope']);
    const token = process.env[environmentName(entry.tokenEnv)];
    if (!token) fail('MAP_CREDENTIAL_REQUIRED');
    return { token, scope: validateReadScope(entry.scope) };
  });
  if (config.viewerDirectory !== undefined && typeof config.viewerDirectory !== 'string') fail('MAP_CONFIG_INVALID');
  const store = createNeo4jMapStore({
    uri: database.uri,
    username: database.username,
    password,
    ...(database.database === undefined ? {} : { database: database.database }),
    // Optional read limits; the store checks their type and hard maximum.
    ...Object.fromEntries(STORE_LIMITS.filter(key => database[key] !== undefined).map(key => [key, database[key]])),
  });
  try {
    const server = await startMapServer({
      service: new MapService(store),
      credentials,
      port: integer(config.port, 8789, 0, 65535),
      ...(config.viewerDirectory === undefined ? {} : { viewerDirectory: resolve(config.viewerDirectory) }),
    });
    process.stdout.write(`${JSON.stringify({ url: server.url, mode: 'read-only' })}\n`);
    await new Promise<void>(done => {
      const stop = (): void => {
        process.off('SIGINT', stop);
        process.off('SIGTERM', stop);
        done();
      };
      process.once('SIGINT', stop);
      process.once('SIGTERM', stop);
    });
    await server.close();
  } finally {
    await store.close();
  }
}
if (isCliEntry(import.meta)) {
  void runMapCli().catch(error => reportStartupFailure(error, USAGE));
}
