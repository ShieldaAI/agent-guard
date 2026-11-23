import { GuardErrorCatalog, type GuardErrorCodeValue } from '@shieldaai/agent-guard';
import { modelMessage } from './outcomes.js';

/** What a code means, for people reading logs, and what the model is told. */
export interface CodeExplanation {
  readonly code: string;
  /** 'guard' for a GuardError code, 'adapter' for a code the adapters add. */
  readonly source: 'guard' | 'adapter';
  readonly meaning: string;
  readonly cause: string;
  readonly retryable: boolean;
  /** The sentence the dispatcher sends to the model for this code. */
  readonly modelMessage: string;
}

const ADAPTER_CODES: Readonly<Record<string, { meaning: string; cause: string }>> = Object.freeze({
  INPUT_NOT_JSON: {
    meaning: 'The provider sent tool arguments that are not valid JSON text.',
    cause: 'The model produced malformed arguments. Nothing ran; the model is asked to resend a JSON object.',
  },
  APPROVAL_QUEUE_FULL: {
    meaning: 'Too many actions already wait for a person.',
    cause: 'Reviewers are behind, or a model keeps requesting approvals. Clear the queue or raise maxPending.',
  },
  APPROVAL_REJECTED: {
    meaning: 'A person denied the action in the approval queue.',
    cause: 'ApprovalQueue.reject() was called. Nothing ran.',
  },
  APPROVAL_TIMEOUT: {
    meaning: 'Nobody decided before the dispatcher stopped waiting.',
    cause: 'waitForApproval.timeoutMs passed. The action was dropped from the queue; nothing ran.',
  },
  APPROVAL_UNAVAILABLE: {
    meaning: 'The action needs approval and the dispatcher has no approval queue.',
    cause: 'Pass an ApprovalQueue to createDispatcher(), or do not route approval-requiring tools to this task.',
  },
  HOST_ERROR: {
    meaning: 'Host code threw something that is not a guard decision.',
    cause:
      "A tool backend or the connection to a remote executor failed. The model got no detail; the error went to the dispatcher's onHostError hook. If it happened during execute, the effect is unknown.",
  },
  APPROVAL_CANCELLED: {
    meaning: 'The wait for approval was aborted by the caller.',
    cause: "The dispatch call's AbortSignal fired. The action was dropped from the queue; nothing ran.",
  },
});

/** Explains a guard or adapter code. Returns undefined for an unknown code. */
export function explainCode(code: string): CodeExplanation | undefined {
  if (Object.hasOwn(GuardErrorCatalog, code)) {
    const info = GuardErrorCatalog[code as GuardErrorCodeValue];
    return Object.freeze({
      code,
      source: 'guard',
      meaning: info.meaning,
      cause: info.cause,
      retryable: info.retryable,
      modelMessage: modelMessage(code),
    });
  }
  if (!Object.hasOwn(ADAPTER_CODES, code)) return undefined;
  const adapter = ADAPTER_CODES[code]!;
  return Object.freeze({ code, source: 'adapter', ...adapter, retryable: false, modelMessage: modelMessage(code) });
}

/** Every code `explainCode` knows, sorted. */
export function knownCodes(): readonly string[] {
  return Object.freeze([...Object.keys(GuardErrorCatalog), ...Object.keys(ADAPTER_CODES)].sort());
}
