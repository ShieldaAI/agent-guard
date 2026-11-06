// Local probe only: compare the peer's certificate bytes with the configured
// certificate. No secret, cookie, or authority token is sent to this endpoint.
import { readFileSync } from 'node:fs';
import { timingSafeEqual } from 'node:crypto';
import { get } from 'node:https';
import { checkServerIdentity } from 'node:tls';
import { isIP } from 'node:net';
import { validateCertificate } from '../../apps/agent-ops/tls-policy.mjs';
try {
  const config = JSON.parse(readFileSync(process.argv[2], 'utf8'));
  const certificate = readFileSync(config.tls.certFile);
  const origin = new URL(config.publicOrigin), expected = validateCertificate(certificate, config.publicOrigin).cert.raw;
  const port = config.port ?? 8443;
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw Error('INVALID_PROBE_PORT');
  // Only the configured public certificate is trusted. Partial-chain trust
  // permits a company-issued leaf without disabling TLS verification or loading
  // system CAs. The exact leaf pin is checked again after the handshake.
  const request = get({ hostname: '127.0.0.1', port, path: '/health/ready',
    ...(isIP(origin.hostname) ? {} : { servername: origin.hostname }), headers: { Host: origin.host },
    ca: certificate, allowPartialTrustChain: true, rejectUnauthorized: true, minVersion: 'TLSv1.2',
    checkServerIdentity: (_host, peer) => {
      const identityError = checkServerIdentity(origin.hostname, peer);
      if (identityError) return identityError;
      if (peer.raw?.length !== expected.length || !timingSafeEqual(peer.raw, expected)) return Error('HEALTH_CERTIFICATE_MISMATCH');
    }, timeout: 3000 }, response => {
    const actual = response.socket.getPeerCertificate().raw;
    const valid = actual?.length === expected.length && timingSafeEqual(actual, expected) && response.statusCode === 200;
    process.exitCode = valid ? 0 : 1;
    response.destroy(); // The probe needs no response body or unbounded stream.
  });
  const deadline = setTimeout(() => request.destroy(Error('PROBE_DEADLINE')), 3000);
  request.on('close', () => clearTimeout(deadline));
  request.on('timeout', () => request.destroy());
  request.on('error', () => { process.exitCode = 1; });
} catch { process.exitCode = 1; }
