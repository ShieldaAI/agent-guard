import { immutableJson, type Json } from '@shieldaai/agent-guard';

/** Preserve fractional measurements, but never let rounding manufacture a passing integer count. */
function checkNumber(token: string): void {
  const value = Number(token);
  if (!Number.isFinite(value)) throw new Error('Invalid evidence number');
  if (!Number.isInteger(value)) return;
  if (!Number.isSafeInteger(value)) throw new Error('Invalid evidence integer');
  const [mantissa, exponent] = token.split(/[eE]/u);
  const [whole, fraction = ''] = mantissa!.replace(/^-/, '').split('.');
  const places = fraction.length - Number(exponent ?? 0);
  if (places > 0 && /[1-9]/u.test((whole + fraction).slice(-places))) throw new Error('Fractional evidence integer');
}

/** JSON.parse checks grammar, but rounds numbers and discards duplicate object members. Inspect original tokens too. */
export function parseEvidenceJson(bytes: Uint8Array, maxBytes: number): Json {
  if (bytes.byteLength > maxBytes) throw new Error('Evidence exceeds the byte limit');
  const source = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes);
  const statement = immutableJson(JSON.parse(source), 24, 8192, maxBytes);
  const objects: Set<string>[] = [];
  for (const match of source.matchAll(/"(?:[^"\\]|\\.)*"|[{}:]|-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?/gu)) {
    const token = match[0];
    if (token === '{') objects.push(new Set());
    else if (token === '}') objects.pop();
    else if (token.startsWith('"')) {
      let next = match.index! + token.length;
      while (next < source.length && /[ \t\r\n]/u.test(source[next]!)) next++;
      if (source[next] !== ':') continue;
      const name = JSON.parse(token) as string;
      const keys = objects.at(-1)!;
      if (keys.has(name)) throw new Error('Duplicate JSON member in evidence');
      keys.add(name);
    } else if (token !== ':') checkNumber(token);
  }
  return statement;
}
