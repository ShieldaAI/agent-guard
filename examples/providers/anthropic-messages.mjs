import { runTicketWorkflow } from './workflow.mjs';
import { isEntry, runOfflineExample } from './replay.mjs';

export function runAnthropicTicketWorkflow(options) {
  return runTicketWorkflow({ ...options, provider: 'anthropic' });
}

if (isEntry(import.meta)) {
  await runOfflineExample('anthropic', runAnthropicTicketWorkflow);
}
