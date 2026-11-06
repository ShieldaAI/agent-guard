import { createPrivateKey, X509Certificate } from 'node:crypto';
import { isIP } from 'node:net';

function invalid(code) { throw Object.assign(new Error(code), { code }); }

/** Validate the served leaf independently of a probe's local certificate pin. */
export function validateCertificate(certBytes, publicOrigin, now = Date.now()) {
  let origin;
  try { origin = new URL(publicOrigin); } catch { invalid('PUBLIC_ORIGIN_INVALID'); }
  if (origin.protocol !== 'https:' || origin.origin !== publicOrigin || origin.username || origin.password) invalid('PUBLIC_ORIGIN_INVALID');
  try {
    const cert = new X509Certificate(certBytes), host = origin.hostname.replace(/^\[|\]$/g, '');
    const validFrom = Date.parse(cert.validFrom), expiresAt = Date.parse(cert.validTo);
    if (!Number.isFinite(now) || !Number.isFinite(validFrom) || !Number.isFinite(expiresAt) ||
        validFrom > now || expiresAt <= now || !(isIP(host) ? cert.checkIP(host) : cert.checkHost(host))) invalid('TLS_CERTIFICATE_INVALID');
    return { cert, validFrom, expiresAt };
  } catch { invalid('TLS_CERTIFICATE_INVALID'); }
}

export function validateTls(tls, publicOrigin, now = Date.now()) {
  const { cert, expiresAt } = validateCertificate(tls.cert, publicOrigin, now);
  try { if (!cert.checkPrivateKey(createPrivateKey(tls.key))) invalid('TLS_CERTIFICATE_INVALID'); }
  catch { invalid('TLS_CERTIFICATE_INVALID'); }
  return { expiresAt };
}
