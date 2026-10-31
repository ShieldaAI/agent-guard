#!/usr/bin/env node
import { constants } from 'node:fs';
import { open } from 'node:fs/promises';
import { resolve } from 'node:path';
import { parseArgs } from 'node:util';
import { pathToFileURL } from 'node:url';
import { createNeo4jMapStore } from './store.js';
import { MapService } from './service.js';
import { startMapServer, type MapCredential } from './http.js';
import { validateReadScope } from './types.js';
import { fields, fail, integer, parseRequest } from './boundary.js';

function environmentName(value: unknown): string {
  if (typeof value !== 'string' || !/^[A-Za-z_][A-Za-z0-9_]{0,127}$/.test(value)) fail('MAP_CONFIG_INVALID');
  return value;
}
/** Keep the type check and bounded read on one nonblocking descriptor. */
async function configBytes(path: string): Promise<Buffer> {
  if (typeof constants.O_NONBLOCK !== 'number') fail('MAP_CONFIG_INVALID');
  const maximum = 128 * 1024;
  const file = await open(path, constants.O_RDONLY | constants.O_NONBLOCK);
  try {
    const info = await file.stat();
    if (!info.isFile() || info.size > maximum) fail('MAP_CONFIG_INVALID');
    // The file may grow after stat; never use an unbounded readFile here.
    const data = Buffer.alloc(maximum + 1); let bytes = 0;
    while (bytes < data.length) {
      const read = await file.read(data, bytes, data.length - bytes, null);
      if (!read.bytesRead) break;
      bytes += read.bytesRead;
    }
    if (bytes > maximum) fail('MAP_CONFIG_INVALID');
    return data.subarray(0, bytes);
  } finally { await file.close(); }
}
/** Credential values stay in the environment and are never printed by this launcher. */
export async function runMapCli(argv: string[] = process.argv.slice(2)): Promise<void> {
  const { values } = parseArgs({ args: argv, options: { config: { type: 'string' }, help: { type: 'boolean' } }, strict: true });
  if (values.help) { process.stdout.write('agent-guard-map --config HOST_CONFIG.json\n'); return; }
  if (!values.config) fail('MAP_CONFIG_INVALID');
  const path = resolve(values.config);
  const config = fields(parseRequest(await configBytes(path), 128 * 1024), ['neo4j', 'credentials', 'port', 'viewerDirectory'], ['neo4j', 'credentials']);
  const database = fields(config.neo4j, ['uri', 'username', 'passwordEnv', 'database'], ['uri', 'username', 'passwordEnv']);
  if (typeof database.uri !== 'string' || typeof database.username !== 'string' ||
      (database.database !== undefined && typeof database.database !== 'string')) fail('MAP_CONFIG_INVALID');
  const password = process.env[environmentName(database.passwordEnv)]; if (!password) fail('MAP_CREDENTIAL_REQUIRED');
  if (!Array.isArray(config.credentials) || config.credentials.length < 1 || config.credentials.length > 128) fail('MAP_CONFIG_INVALID');
  const credentials: MapCredential[] = config.credentials.map(value => {
    const entry = fields(value, ['tokenEnv', 'scope'], ['tokenEnv', 'scope']);
    const token = process.env[environmentName(entry.tokenEnv)]; if (!token) fail('MAP_CREDENTIAL_REQUIRED');
    return { token, scope: validateReadScope(entry.scope) };
  });
  if (config.viewerDirectory !== undefined && typeof config.viewerDirectory !== 'string') fail('MAP_CONFIG_INVALID');
  const store = createNeo4jMapStore({ uri: database.uri, username: database.username, password,
    ...(database.database === undefined ? {} : { database: database.database }) });
  try {
    const server = await startMapServer({ service: new MapService(store), credentials,
      port: integer(config.port, 8789, 0, 65535),
      ...(config.viewerDirectory === undefined ? {} : { viewerDirectory: resolve(config.viewerDirectory) }) });
    process.stdout.write(`${JSON.stringify({ url: server.url, mode: 'read-only' })}\n`);
    await new Promise<void>(done => {
      const stop = (): void => { process.off('SIGINT', stop); process.off('SIGTERM', stop); done(); };
      process.once('SIGINT', stop); process.once('SIGTERM', stop);
    });
    await server.close();
  } finally { await store.close(); }
}
if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  void runMapCli().catch(() => { process.stderr.write('MAP_START_FAILED\n'); process.exitCode = 1; });
}
