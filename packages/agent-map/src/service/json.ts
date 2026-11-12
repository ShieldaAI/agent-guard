import type { JsonObject } from '../types.js';

/**
 * The map's record interfaces (`MapCoverage`, `MapPolicyEvidence`, flag results and so on) hold
 * only JSON values, but an interface has no index signature, so TypeScript will not treat one as
 * a `JsonObject`. These two helpers are the only place that says so.
 */
export const jsonObject = (value: object): JsonObject => value as JsonObject;
export const jsonList = (values: readonly object[]): readonly JsonObject[] => values as readonly JsonObject[];
