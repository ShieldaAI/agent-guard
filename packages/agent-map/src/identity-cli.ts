#!/usr/bin/env node
import { dirname, resolve } from 'node:path';
import { parseArgs } from 'node:util';
import { PACKAGE_VERSION, STORE_LIMITS, isCliEntry, reportStartupFailure } from './cli-entry.js';
import { createNeo4jMapStore } from './store.js';
import { MapService } from './service.js';
import { startMapIdentityServer, type MapIdentityServerOptions } from './identity-http.js';
import { fail } from './common.js';
import { fields, parseRequest, readHostFile } from './boundary.js';

function environment(value: unknown): string {
  if (typeof value !== 'string' || !/^[A-Za-z_][A-Za-z0-9_]{0,127}$/.test(value)) fail('MAP_CONFIG_INVALID');
  const secret = process.env[value];
  if (!secret || Buffer.byteLength(secret) > 65_536) fail('MAP_CREDENTIAL_REQUIRED');
  return secret;
}
/**
 * The company launcher holds a TLS key and names secrets, so its files are this user's own
 * regular files, never a link, and private inputs exclude group and other access.
 */
async function boundedFile(path: string, maximum: number, privateFile: boolean): Promise<string> {
  const bytes = await readHostFile(path, maximum, {
    noFollow: true,
    owner: 'service',
    singleLink: true,
    private: privateFile,
  });
  return new TextDecoder('utf-8', { fatal: true }).decode(bytes);
}
export async function loadMapIdentityConfig(
  filename: string,
): Promise<{ server: Omit<MapIdentityServerOptions, 'service'>; database: Parameters<typeof createNeo4jMapStore>[0] }> {
  const path = resolve(filename),
    directory = dirname(path);
  const config = fields(
    parseRequest(Buffer.from(await boundedFile(path, 128 * 1024, true)), 128 * 1024),
    [
      'neo4j',
      'publicOrigin',
      'tls',
      'oidc',
      'companyId',
      'bindings',
      'listenHost',
      'port',
      'viewerDirectory',
      'sessionTtlMs',
      'loginTtlMs',
      'maxSessions',
      'maxLoginTransactions',
      'requestTimeoutMs',
      'maxRequestBytes',
      'maxResponseBytes',
      'maxConcurrentRequests',
      'rateLimit',
    ],
    ['neo4j', 'publicOrigin', 'tls', 'oidc', 'companyId', 'bindings'],
  );
  const db = fields(
    config.neo4j,
    ['uri', 'username', 'passwordEnv', 'database', ...STORE_LIMITS],
    ['uri', 'username', 'passwordEnv'],
  );
  if (
    typeof db.uri !== 'string' ||
    typeof db.username !== 'string' ||
    (db.database !== undefined && typeof db.database !== 'string')
  )
    fail('MAP_CONFIG_INVALID');
  const database = {
    uri: db.uri,
    username: db.username,
    password: environment(db.passwordEnv),
    ...(db.database === undefined ? {} : { database: db.database }),
    // Optional read limits; the store checks their type and hard maximum.
    ...Object.fromEntries(STORE_LIMITS.filter(key => db[key] !== undefined).map(key => [key, db[key]])),
  };
  const tls = fields(config.tls, ['keyFile', 'certFile'], ['keyFile', 'certFile']);
  const oidc = fields(
    config.oidc,
    [
      'issuer',
      'clientId',
      'clientSecretEnv',
      'clientAuthMethod',
      'endpointOrigins',
      'caFile',
      'requestTimeoutMs',
      'maxResponseBytes',
      'clockToleranceSeconds',
    ],
    ['issuer', 'clientId', 'clientSecretEnv'],
  );
  for (const value of [tls.keyFile, tls.certFile]) if (typeof value !== 'string' || !value) fail('MAP_CONFIG_INVALID');
  if (oidc.caFile !== undefined && (typeof oidc.caFile !== 'string' || !oidc.caFile)) fail('MAP_CONFIG_INVALID');
  if (config.viewerDirectory !== undefined && typeof config.viewerDirectory !== 'string') fail('MAP_CONFIG_INVALID');
  const { neo4j: _database, tls: _tls, oidc: _oidc, ...server } = config;
  const { clientSecretEnv: _secret, caFile: _ca, ...provider } = oidc;
  return {
    database,
    server: {
      ...server,
      tls: {
        key: await boundedFile(resolve(directory, tls.keyFile as string), 256 * 1024, true),
        cert: await boundedFile(resolve(directory, tls.certFile as string), 256 * 1024, false),
      },
      oidc: {
        ...provider,
        clientSecret: environment(oidc.clientSecretEnv),
        ...(oidc.caFile === undefined
          ? {}
          : { ca: await boundedFile(resolve(directory, oidc.caFile as string), 256 * 1024, false) }),
      },
      ...(config.viewerDirectory === undefined ? {} : { viewerDirectory: resolve(directory, config.viewerDirectory) }),
    } as Omit<MapIdentityServerOptions, 'service'>,
  };
}
const USAGE = 'agent-guard-map-identity --config PRIVATE_HOST_CONFIG.json | --help | --version';
/** Restart reloads policy/secrets and invalidates sessions; credentials are never printed. */
export async function runMapIdentityCli(argv: string[] = process.argv.slice(2)): Promise<void> {
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
  const config = await loadMapIdentityConfig(values.config);
  const store = createNeo4jMapStore(config.database);
  try {
    const server = await startMapIdentityServer({ ...config.server, service: new MapService(store) });
    try {
      process.stdout.write(`${JSON.stringify({ url: server.url, mode: 'oidc-read-only' })}\n`);
      await new Promise<void>(done => {
        const stop = (): void => {
          process.off('SIGINT', stop);
          process.off('SIGTERM', stop);
          done();
        };
        process.once('SIGINT', stop);
        process.once('SIGTERM', stop);
      });
    } finally {
      await server.close();
    }
  } finally {
    await store.close();
  }
}
if (isCliEntry(import.meta)) {
  void runMapIdentityCli().catch(error => reportStartupFailure(error, USAGE));
}
