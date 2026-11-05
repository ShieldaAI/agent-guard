import { runTicketWorkflow } from './workflow.mjs';
import { isEntry, runOfflineExample } from './replay.mjs';

export function runOpenAITicketWorkflow(options) {
  return runTicketWorkflow({ ...options, provider: 'openai' });
}

if (isEntry(import.meta)) {
  await runOfflineExample('openai', runOpenAITicketWorkflow);
}
