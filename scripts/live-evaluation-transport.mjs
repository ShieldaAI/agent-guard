// Checkout evaluation transport for the host-owned synthetic ticket workflow.
import { canonicalJson, immutableJson } from '@shieldaai/agent-guard/internal';
import { createRestrictedFetch } from '@shieldaai/agent-guard-executor';
import { ticketRequest } from '../examples/providers/workflow.mjs';

const endpoints = {
  openai: 'https://api.openai.com/v1/responses',
  anthropic: 'https://api.anthropic.com/v1/messages',
};
const MAX_BYTES = 64 * 1024;
const { parseEvidenceJson } = await import(
  new URL('./evidence-json.js', import.meta.resolve('@shieldaai/agent-guard-executor'))
);

export function createLiveEvaluationTransport({ provider, model, apiKey, maxOutputTokens }) {
  if (
    (provider !== 'openai' && provider !== 'anthropic') ||
    typeof model !== 'string' ||
    !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(model) ||
    typeof apiKey !== 'string' ||
    !/^[!-~]{1,4096}$/.test(apiKey) ||
    !Number.isSafeInteger(maxOutputTokens) ||
    maxOutputTokens < 16 ||
    maxOutputTokens > 4096
  ) {
    throw new Error('Invalid provider evaluation transport configuration');
  }
  const endpoint = endpoints[provider];
  const send = createRestrictedFetch({
    allowedOrigins: [new URL(endpoint).origin],
    maxRequestBytes: MAX_BYTES,
    maxResponseBytes: MAX_BYTES,
    timeoutMs: 60_000,
  });
  const auth =
    provider === 'openai'
      ? { authorization: 'Bearer ' + apiKey }
      : { 'x-api-key': apiKey, 'anthropic-version': '2023-06-01' };
  return async (request, { signal }) => {
    try {
      signal.throwIfAborted();
      const captured = immutableJson(request, 24, 10_000, MAX_BYTES);
      const history = provider === 'openai' ? captured.input : captured.messages;
      if (!Array.isArray(history) || history.length === 0) throw new Error();
      const expected = ticketRequest(provider, model, history, maxOutputTokens);
      // An extra hosted tool, a different model, or a change to the output cap invalidates the request.
      if (canonicalJson(captured) !== canonicalJson(expected)) throw new Error();
      const response = await send(endpoint, {
        method: 'POST',
        signal,
        redirect: 'error',
        headers: { ...auth, 'content-type': 'application/json', accept: 'application/json' },
        body: JSON.stringify(captured),
      });
      if (
        response.status !== 200 ||
        response.headers.get('content-type')?.split(';')[0].trim().toLowerCase() !== 'application/json'
      ) {
        await response.body?.cancel();
        throw new Error();
      }
      // The restricted reader counts incoming bytes even for a chunked body.
      const bytes = new Uint8Array(await response.arrayBuffer());
      signal.throwIfAborted();
      return parseEvidenceJson(bytes, MAX_BYTES);
    } catch {
      // HTTP errors and abort reasons may contain source content, provider diagnostics or secrets.
      throw new Error('Live provider request failed');
    }
  };
}
