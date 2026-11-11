import { type Json } from '@shieldaai/agent-guard';
import { immutableJson } from '@shieldaai/agent-guard/internal';

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
export function parseEvidenceJson(bytes: Uint8Array, maxBytes: number, maxNodes = 8192): Json {
  // Host-selected bounded expansion supports bulk enrollment without relaxing
  // the default provider/evidence parser budget or duplicate/numeric checks.
  if (!Number.isSafeInteger(maxNodes) || maxNodes < 1 || maxNodes > 100_000) throw new Error('Invalid JSON node limit');
  if (bytes.byteLength > maxBytes) throw new Error('Evidence exceeds the byte limit');
  const source = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes);
  const statement = immutableJson(JSON.parse(source), 24, maxNodes, maxBytes);
  const objects: Set<string>[] = [];
  // Walk the already validated JSON once. Avoid a searching/backtracking regular
  // expression on long escaped strings supplied by providers or evidence files.
  for (let offset = 0; offset < source.length;) {
    const char = source[offset]!;
    if (char === '{') {
      objects.push(new Set());
      offset++;
    } else if (char === '}') {
      objects.pop();
      offset++;
    } else if (char === '"') {
      const start = offset++;
      while (offset < source.length) {
        const current = source[offset++];
        if (current === '\\')
          offset++; // JSON.parse already checked the escape grammar.
        else if (current === '"') break;
      }
      let next = offset;
      while (source[next] === ' ' || source[next] === '\t' || source[next] === '\r' || source[next] === '\n') next++;
      if (source[next] !== ':') continue;
      const name = JSON.parse(source.slice(start, offset)) as string;
      const keys = objects.at(-1)!;
      if (keys.has(name)) throw new Error('Duplicate JSON member in evidence');
      keys.add(name);
    } else if (char === '-' || (char >= '0' && char <= '9')) {
      const start = offset++;
      while (offset < source.length) {
        const current = source[offset]!;
        if (
          (current >= '0' && current <= '9') ||
          current === '.' ||
          current === 'e' ||
          current === 'E' ||
          current === '+' ||
          current === '-'
        )
          offset++;
        else break;
      }
      checkNumber(source.slice(start, offset));
    } else offset++;
  }
  return statement;
}
