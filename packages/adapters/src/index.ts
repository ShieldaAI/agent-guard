// Shielda Agent Guard adapters: connect the guard to model providers and agent frameworks.
// No third-party runtime dependencies; framework factories are passed in by the caller.
export { AdapterError, isAdapterError, type AdapterErrorCode } from './errors.js';
export {
  modelMessage,
  outcomeForModel,
  outcomeFromError,
  isErrorOutcome,
  type AdapterCode,
  type OutcomeCode,
  type DispatchOutcome,
  type OkOutcome,
  type DeniedOutcome,
  type WaitingOutcome,
  type FailedOutcome,
} from './outcomes.js';
export {
  createDispatcher,
  ApprovalQueue,
  guardBackend,
  executorBackend,
  executorClientBackend,
  type Dispatcher,
  type DispatcherOptions,
  type ToolCall,
  type PreparedCall,
  type GuardBackend,
  type ExecutorLike,
  type ExecutorClientLike,
  type PendingApproval,
  type ApprovalQueueOptions,
} from './dispatcher.js';
export {
  toolSpecs,
  registerApprovedTools,
  taskBudget,
  type ToolSpec,
  type ToolDefinitionSource,
  type RegisterOptions,
  type JsonObject,
  type PlainJson,
  type ObjectSchema,
} from './tools.js';
export {
  jsonSchemaParser,
  validateJsonSchema,
  hasNestedQuantifier,
  type JsonSchemaOptions,
  type SchemaIssue,
} from './json-schema.js';
export { standardSchemaParser, type StandardSchemaLike } from './standard-schema.js';
export {
  combinePolicies,
  denyWhen,
  requireApprovalWhen,
  denyTools,
  requireApprovalForTools,
  requireApprovalForExternal,
  requireApprovalAfterUntrusted,
  withinHours,
  type ActionPredicate,
} from './policies.js';
export {
  combineDecisionHooks,
  jsonLinesDecisionLogger,
  openTelemetryDecisionHook,
  DecisionStats,
  type DecisionHook,
  type DecisionStatsSnapshot,
  type MeterLike,
  type SpanLike,
} from './observability.js';
export {
  parseToolArguments,
  safeDispatch,
  anthropicTools,
  anthropicToolResults,
  openAIResponsesTools,
  openAIResponsesToolOutputs,
  openAIChatTools,
  openAIChatToolMessages,
  geminiTools,
  geminiFunctionResponses,
  bedrockTools,
  bedrockToolResults,
  type RunOptions,
  type AnthropicTool,
  type AnthropicToolResult,
  type OpenAIResponsesTool,
  type OpenAIFunctionCallOutput,
  type OpenAIChatTool,
  type OpenAIChatToolMessage,
  type GeminiTool,
  type GeminiFunctionResponsePart,
  type BedrockTool,
  type BedrockToolResult,
} from './providers.js';
export {
  aiSdkTools,
  openAIAgentsTools,
  langChainTools,
  mcpServerTools,
  registerMcpServerTools,
  type McpServerLike,
  type AiSdkTool,
  type OpenAIAgentsToolConfig,
  type LangChainToolFields,
  type McpCallToolResult,
} from './frameworks.js';
export { explainCode, knownCodes, type CodeExplanation } from './explain.js';
export { RateLimiter, type RateLimitRule } from './rate-limit.js';
export { defineTool, type TypedToolDefinition } from './typed-tools.js';
