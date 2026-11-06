// Local probe only: compare the peer's certificate bytes with the configured
// certificate. No secret, cookie, or authority token is sent to this endpoint.
import { readFileSync } from 'node:fs';
import { timingSafeEqual } from 'node:crypto';
import { get } from 'node:https';
import { validateCertificate } from '../../apps/agent-ops/tls-policy.mjs';
try {
  const config = JSON.parse(readFileSync(process.argv[2], 'utf8'));
  const origin = new URL(config.publicOrigin), expected = validateCertificate(readFileSync(config.tls.certFile), config.publicOrigin).cert.raw;
  const request = get({ hostname: '127.0.0.1', port: config.port ?? 8443, path: '/health/ready',
    servername: origin.hostname, headers: { Host: origin.host }, rejectUnauthorized: false, timeout: 3000 }, response => {
    const actual = response.socket.getPeerCertificate().raw;
    const valid = actual?.length === expected.length && timingSafeEqual(actual, expected) && response.statusCode === 200;
    response.resume(); process.exitCode = valid ? 0 : 1;
  });
  request.on('timeout', () => request.destroy());
  request.on('error', () => { process.exitCode = 1; });
} catch { process.exitCode = 1; }
