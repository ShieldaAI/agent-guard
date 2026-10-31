#!/usr/bin/env node
import { constants } from 'node:fs';
import { open } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { parseArgs } from 'node:util';
import { pathToFileURL } from 'node:url';
import { createNeo4jMapStore } from './store.js';
import { MapService } from './service.js';
import { startMapIdentityServer, type MapIdentityServerOptions } from './identity-http.js';
import { fields, fail, parseRequest } from './boundary.js';

function environment(value: unknown): string {
  if (typeof value !== 'string' || !/^[A-Za-z_][A-Za-z0-9_]{0,127}$/.test(value)) fail('MAP_CONFIG_INVALID');
  const secret = process.env[value];
  if (!secret || Buffer.byteLength(secret) > 65_536) fail('MAP_CREDENTIAL_REQUIRED');
  return secret;
}
/** POSIX launcher: owned regular files only; private inputs exclude group/other access. */
async function boundedFile(path: string, maximum: number, privateFile: boolean): Promise<string> {
  if (typeof process.getuid !== 'function' || !constants.O_NOFOLLOW) fail('MAP_CONFIG_INVALID');
  const file = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const info = await file.stat();
    if (!info.isFile() || info.nlink !== 1 || info.uid !== process.getuid() || info.size > maximum ||
        (privateFile && (info.mode & 0o077) !== 0) || (info.mode & 0o022) !== 0) fail('MAP_CONFIG_INVALID');
    const data = Buffer.alloc(maximum + 1); let bytes = 0;
    while (bytes < data.length) { const read = await file.read(data, bytes, data.length - bytes, null); if (!read.bytesRead) break; bytes += read.bytesRead; }
    if (bytes > maximum) fail('MAP_CONFIG_INVALID');
    return new TextDecoder('utf-8', { fatal: true }).decode(data.subarray(0, bytes));
  } finally { await file.close(); }
}
export async function loadMapIdentityConfig(filename: string): Promise<{ server: Omit<MapIdentityServerOptions, 'service'>; database: Parameters<typeof createNeo4jMapStore>[0] }> {
  const path = resolve(filename), directory = dirname(path);
  const config = fields(parseRequest(Buffer.from(await boundedFile(path, 128 * 1024, true)), 128 * 1024),
    ['neo4j', 'publicOrigin', 'tls', 'oidc', 'companyId', 'bindings', 'listenHost', 'port', 'viewerDirectory',
      'sessionTtlMs', 'loginTtlMs', 'maxSessions', 'maxLoginTransactions', 'requestTimeoutMs', 'maxRequestBytes',
      'maxResponseBytes', 'maxConcurrentRequests', 'rateLimit'], ['neo4j', 'publicOrigin', 'tls', 'oidc', 'companyId', 'bindings']);
  const db = fields(config.neo4j, ['uri', 'username', 'passwordEnv', 'database'], ['uri', 'username', 'passwordEnv']);
  if (typeof db.uri !== 'string' || typeof db.username !== 'string' || (db.database !== undefined && typeof db.database !== 'string')) fail('MAP_CONFIG_INVALID');
  const database = { uri: db.uri, username: db.username, password: environment(db.passwordEnv), ...(db.database === undefined ? {} : { database: db.database }) };
  const tls = fields(config.tls, ['keyFile', 'certFile'], ['keyFile', 'certFile']);
  const oidc = fields(config.oidc, ['issuer', 'clientId', 'clientSecretEnv', 'clientAuthMethod', 'endpointOrigins', 'caFile', 'requestTimeoutMs', 'maxResponseBytes'], ['issuer', 'clientId', 'clientSecretEnv']);
  for (const value of [tls.keyFile, tls.certFile]) if (typeof value !== 'string' || !value) fail('MAP_CONFIG_INVALID');
  if (oidc.caFile !== undefined && (typeof oidc.caFile !== 'string' || !oidc.caFile)) fail('MAP_CONFIG_INVALID');
  if (config.viewerDirectory !== undefined && typeof config.viewerDirectory !== 'string') fail('MAP_CONFIG_INVALID');
  const { neo4j: _database, tls: _tls, oidc: _oidc, ...server } = config;
  const { clientSecretEnv: _secret, caFile: _ca, ...provider } = oidc;
  return { database, server: { ...server,
    tls: { key: await boundedFile(resolve(directory, tls.keyFile as string), 256 * 1024, true),
      cert: await boundedFile(resolve(directory, tls.certFile as string), 256 * 1024, false) },
    oidc: { ...provider, clientSecret: environment(oidc.clientSecretEnv),
      ...(oidc.caFile === undefined ? {} : { ca: await boundedFile(resolve(directory, oidc.caFile as string), 256 * 1024, false) }) },
    ...(config.viewerDirectory === undefined ? {} : { viewerDirectory: resolve(directory, config.viewerDirectory) }),
  } as Omit<MapIdentityServerOptions, 'service'> };
}
/** Restart reloads policy/secrets and invalidates sessions; credentials are never printed. */
export async function runMapIdentityCli(argv: string[] = process.argv.slice(2)): Promise<void> {
  const { values } = parseArgs({ args: argv, options: { config: { type: 'string' }, help: { type: 'boolean' } }, strict: true });
  if (values.help) { process.stdout.write('agent-guard-map-identity --config PRIVATE_HOST_CONFIG.json\n'); return; }
  if (!values.config) fail('MAP_CONFIG_INVALID');
  const config = await loadMapIdentityConfig(values.config);
  const store = createNeo4jMapStore(config.database);
  try {
    const server = await startMapIdentityServer({ ...config.server, service: new MapService(store) });
    try {
      process.stdout.write(`${JSON.stringify({ url: server.url, mode: 'oidc-read-only' })}\n`);
      await new Promise<void>(done => {
        const stop = (): void => { process.off('SIGINT', stop); process.off('SIGTERM', stop); done(); };
        process.once('SIGINT', stop); process.once('SIGTERM', stop);
      });
    } finally { await server.close(); }
  } finally { await store.close(); }
}
if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  void runMapIdentityCli().catch(() => { process.stderr.write('MAP_START_FAILED\n'); process.exitCode = 1; });
}
