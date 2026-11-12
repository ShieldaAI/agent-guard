// Browser stand-in for `node:crypto`. Nothing the demo's MapService runs hashes or draws random
// values; these exist so the import resolves, and fail loudly if that ever stops being true.
const unavailable = name => () => {
  throw new Error(`node:crypto ${name} is not available in the viewer bundle`);
};
export const createHash = unavailable('createHash');
export const randomUUID = unavailable('randomUUID');
