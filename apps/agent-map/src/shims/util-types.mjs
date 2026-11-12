// Browser stand-in for `node:util/types`. A page cannot detect a Proxy; the demo's fixture is
// plain data built in this bundle, so there is none to refuse.
export const isProxy = () => false;
export const isPromise = value => value instanceof Promise;
