import { createHash, createPublicKey, verify, type KeyObject } from 'node:crypto';
import type { Json } from '@shieldaai/agent-guard';

function invalid(): never { throw new Error('Invalid signed evidence'); }

export function boundedBase64(value: Json | undefined, maximum: number): Buffer {
  if (typeof value !== 'string' || !value.length || value.length > 4 * Math.ceil(maximum / 3)) invalid();
  const bytes = Buffer.from(value, 'base64');
  if (bytes.length > maximum || bytes.toString('base64') !== value) invalid();
  return bytes;
}

export function enrolledSigningKey(value: Json | undefined): { key: KeyObject; signerSha256: string } {
  if (typeof value !== 'string' || value.length > 2048) invalid();
  const match =
    /^-----BEGIN PUBLIC KEY-----\r?\n([A-Za-z0-9+/=\r\n]+)\r?\n-----END PUBLIC KEY-----(?:\r?\n)?$/u.exec(
      value,
    );
  if (!match) invalid();
  const der = boundedBase64(match[1]!.replace(/[\r\n]/gu, ''), 1024);
  const key = createPublicKey({ key: der, format: 'der', type: 'spki' });
  if (key.asymmetricKeyType !== 'ed25519' || !key.export({ type: 'spki', format: 'der' }).equals(der))
    invalid();
  return { key, signerSha256: createHash('sha256').update(der).digest('hex') };
}


/** Verify DSSE against the host-selected key and media type before interpreting the original bytes. */
export function verifyEnvelopeBytes(value: Json | undefined, mediaType: string,
  signer: { key: KeyObject; signerSha256: string }, maximum: number): Buffer {
  if (!value || typeof value !== 'object' || Array.isArray(value)) invalid();
  const envelope = value as Readonly<Record<string, Json>>;
  if (Object.keys(envelope).length !== 3 || envelope.payloadType !== mediaType ||
      !Array.isArray(envelope.signatures) || envelope.signatures.length !== 1) invalid();
  const entry = envelope.signatures[0];
  if (!entry || typeof entry !== 'object' || Array.isArray(entry)) invalid();
  const signature = entry as Readonly<Record<string, Json>>;
  if (Object.keys(signature).length !== 2 || signature.keyid !== signer.signerSha256) invalid();
  const bytes = boundedBase64(envelope.payload, maximum);
  const sig = boundedBase64(signature.sig, 64);
  const prefix = Buffer.from(`DSSEv1 ${Buffer.byteLength(mediaType)} ${mediaType} ${bytes.length} `, 'ascii');
  if (sig.length !== 64 || !verify(null, Buffer.concat([prefix, bytes]), signer.key, sig)) invalid();
  return bytes;
}
