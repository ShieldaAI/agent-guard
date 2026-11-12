import { GuardError, type ToolDefinition } from '@shieldaai/agent-guard';
import { ExecutorError } from './store.js';

/**
 * Errors the executor's own tools raise on purpose.
 *
 * execute() reports an error thrown by a host tool handler as TOOL_FAILED (or
 * EXECUTION_ABORTED), with the handler's safe code as `detail`: a handler cannot
 * speak for the executor. The built-in tools (memory, model, adapters, sandbox)
 * document their own codes, so their deliberate refusals are recorded here and
 * keep their code. The record is by error object, not by error class: a host
 * handler cannot produce one.
 */
const refusals = new WeakMap<object, { noEffect: boolean }>();
/** Errors that came out of a host-supplied callback. They are never a built-in tool's refusal. */
const hostErrors = new WeakSet<object>();

/**
 * Marks `error` as a built-in tool's own refusal. `noEffect` states that the refusal
 * happened inside a rolled-back ledger transaction and nothing else ran.
 */
export function toolRefusal<E>(error: E, noEffect = false): E {
  if ((error instanceof ExecutorError || error instanceof GuardError) && !refusals.has(error) && !hostErrors.has(error))
    refusals.set(error, { noEffect });
  return error;
}

function fromHost(error: unknown): unknown {
  if (error !== null && typeof error === 'object') {
    // Whatever it carried before (for example another built-in tool's refusal the callback let
    // through), it now speaks for the host callback only.
    refusals.delete(error);
    hostErrors.add(error);
  }
  return error;
}
/**
 * Runs a host-supplied callback (a provider, a credential source, a result sink, a clock) inside a
 * built-in tool. The callback's own error is rethrown unchanged, but it can no longer be recorded
 * as the tool's refusal: execute() reports it as TOOL_FAILED with the error's safe code as
 * `detail`, exactly like an error thrown by a host handler.
 */
export function hostCallback<T>(call: () => T): T {
  let result: T;
  try {
    result = call();
  } catch (error) {
    throw fromHost(error);
  }
  if (result !== null && typeof result === 'object' && typeof (result as { then?: unknown }).then === 'function')
    return (result as unknown as Promise<unknown>).then(undefined, error => {
      throw fromHost(error);
    }) as T;
  return result;
}

export function toolRefusalOf(error: unknown): { noEffect: boolean } | undefined {
  return error !== null && typeof error === 'object' ? refusals.get(error) : undefined;
}

function coded(error: unknown): string | undefined {
  return error instanceof ExecutorError || error instanceof GuardError ? error.code : undefined;
}

/**
 * Wraps a built-in tool's handler so the codes it documents survive execute().
 * `codes` is the tool's documented list (a string matches exactly, a RegExp by test);
 * anything else the handler throws is treated like a host handler error. So is every error
 * from a host callback the tool runs through hostCallback(), whatever its code.
 */
export function builtInExecute(
  execute: ToolDefinition['execute'],
  codes: readonly (string | RegExp)[],
): ToolDefinition['execute'] {
  const mark = (error: unknown): unknown => {
    const code = coded(error);
    if (code !== undefined && codes.some(item => (typeof item === 'string' ? item === code : item.test(code))))
      toolRefusal(error);
    return error;
  };
  return (args, context) => {
    let result: ReturnType<ToolDefinition['execute']>;
    try {
      result = execute(args, context);
    } catch (error) {
      throw mark(error);
    }
    if (result !== null && typeof result === 'object' && typeof (result as { then?: unknown }).then === 'function')
      return (result as Promise<Awaited<typeof result>>).then(undefined, error => {
        throw mark(error);
      });
    return result;
  };
}
