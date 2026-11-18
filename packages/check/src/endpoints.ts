/** Variables that move an agent's model traffic, or load code into the agent. */
export const MODEL_ENDPOINT =
  /^(ANTHROPIC_BASE_URL|ANTHROPIC_BEDROCK_BASE_URL|ANTHROPIC_VERTEX_BASE_URL|ANTHROPIC_FOUNDRY_BASE_URL|OPENAI_BASE_URL|HTTPS?_PROXY|ALL_PROXY|NODE_EXTRA_CA_CERTS|NODE_OPTIONS)$/i;

/** Hosts of model providers: a base URL there moves the traffic to another vendor, not to anyone. */
const PROVIDER_HOST =
  /^https:\/\/([a-z0-9-]+\.)*(anthropic\.com|z\.ai|openai\.com|openrouter\.ai|deepseek\.com|moonshot\.(ai|cn)|bigmodel\.cn|amazonaws\.com|googleapis\.com|azure\.com|cerebras\.ai|groq\.com|together\.xyz|fireworks\.ai|mistral\.ai|x\.ai|minimax(i)?\.(io|chat)|dashscope\.aliyuncs\.com)(:\d+)?(\/|$)/i;

/**
 * How serious an endpoint variable is: a model base URL sends the key and everything the agent
 * reads to that host, and NODE_OPTIONS can load code into the agent itself (high). A known model
 * provider's own host, or a value set outside the repository (`${{ vars.X }}`), is medium; a
 * proxy or CA bundle can intercept traffic but is often a corporate gateway (medium).
 */
export function endpointSeverity(name: string, value = ''): 'high' | 'medium' {
  if (/PROXY|EXTRA_CA_CERTS/i.test(name)) return 'medium';
  if (
    /BASE_URL$/i.test(name) &&
    (PROVIDER_HOST.test(value.trim()) || /^\$\{\{\s*(vars|secrets)\.[A-Za-z0-9_]+\s*\}\}$/.test(value.trim()))
  )
    return 'medium';
  return 'high';
}
