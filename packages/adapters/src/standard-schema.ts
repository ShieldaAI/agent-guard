import type { Json } from '@shieldaai/agent-guard';
import { AdapterError } from './errors.js';

/**
 * The Standard Schema interface (https://standardschema.dev), implemented by Zod 3.24+,
 * Valibot 1, ArkType 2 and others. Only the part this module calls is declared.
 */
export interface StandardSchemaLike {
  readonly '~standard': {
    readonly version: 1;
    readonly validate: (
      value: unknown,
    ) =>
      | { readonly value: unknown; readonly issues?: undefined }
      | { readonly issues: readonly unknown[] }
      | PromiseLike<unknown>;
  };
}

/**
 * A synchronous `parse` for a tool definition from any Standard Schema validator (Zod,
 * Valibot, ArkType, ...). The validator's output becomes the arguments the tool's `resolve`
 * and `execute` receive. A mismatch throws code SCHEMA_MISMATCH; an asynchronous validator
 * (for example a Zod schema with an async refinement) throws SCHEMA_ASYNC, because the guard
 * parses synchronously. Issue messages are never passed on: they can echo the input.
 */
export function standardSchemaParser<Args extends Json = Json>(schema: StandardSchemaLike): (input: Json) => Args {
  const standard = schema?.['~standard'];
  if (!standard || standard.version !== 1 || typeof standard.validate !== 'function')
    throw new AdapterError('INVALID_OPTIONS');
  const validate = standard.validate.bind(standard);
  return function parse(input: Json): Args {
    const result = validate(input);
    if (result !== null && typeof result === 'object' && typeof (result as PromiseLike<unknown>).then === 'function') {
      // Never leave an unhandled rejection behind.
      Promise.resolve(result).catch(() => {});
      throw Object.assign(new Error('Asynchronous schema'), { code: 'SCHEMA_ASYNC' });
    }
    const outcome = result as { value?: unknown; issues?: readonly unknown[] };
    if (outcome.issues !== undefined)
      throw Object.assign(new Error('Arguments do not match the schema'), { code: 'SCHEMA_MISMATCH' });
    return outcome.value as Args;
  };
}
