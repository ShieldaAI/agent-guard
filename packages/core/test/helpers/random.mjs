/** Small seeded PRNG (mulberry32) so property failures reproduce from the printed seed. */
export function random(seed) {
  let state = seed >>> 0;
  const next = () => {
    state = (state + 0x6d2b79f5) >>> 0;
    let t = state;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
  const int = (min, max) => min + Math.floor(next() * (max - min + 1));
  const pick = list => list[int(0, list.length - 1)];
  const shuffle = list => {
    const copy = [...list];
    for (let i = copy.length - 1; i > 0; i--) {
      const j = int(0, i);
      [copy[i], copy[j]] = [copy[j], copy[i]];
    }
    return copy;
  };
  return { next, int, pick, shuffle, bool: () => next() < 0.5 };
}

const ALPHABET = ['a', 'b', 'é', '"', '\\', '\n', ' ', '😀', '0', ' ', '\u0000'];
export function jsonValue(rng, depth = 0) {
  const kind = depth >= 4 ? rng.int(0, 3) : rng.int(0, 5);
  if (kind === 0) return rng.pick([null, true, false]);
  if (kind === 1)
    return rng.pick([0, 1, -1, 1.5, -2.25, 1e21, 2 ** 53 - 1, -(2 ** 53) + 1, 1e-7, rng.int(-1000, 1000)]);
  if (kind === 2 || kind === 3) return Array.from({ length: rng.int(0, 6) }, () => rng.pick(ALPHABET)).join('');
  if (kind === 4) return Array.from({ length: rng.int(0, 4) }, () => jsonValue(rng, depth + 1));
  const object = {};
  for (let i = rng.int(0, 4); i > 0; i--)
    object[Array.from({ length: rng.int(0, 3) }, () => rng.pick(ALPHABET)).join('')] = jsonValue(rng, depth + 1);
  return object;
}
/** The same value with every object's keys inserted in a different order. */
export function reorder(rng, value) {
  if (Array.isArray(value)) return value.map(item => reorder(rng, item));
  if (value === null || typeof value !== 'object') return value;
  const out = {};
  for (const key of rng.shuffle(Object.keys(value))) out[key] = reorder(rng, value[key]);
  return out;
}
