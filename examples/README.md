# Examples

Every example runs offline with synthetic data: no API key, account or external service.
Build once from the repository root (`npm ci --ignore-scripts`, then `npm run build`), then
run a file with `node examples/<file>`.

## Start here

| File | Shows | Prints |
| --- | --- | --- |
| [`basic.mjs`](basic.mjs) | The smallest complete flow: one tool, one task, a person's approval, and the same approval refused when replayed. `npm run demo` runs it. | The result, then `Replay denied: ACTION_USED` |
| [`tool-permissions.mjs`](tool-permissions.mjs) | The three denials you meet first, each before any handler runs: a resource outside the grant, a call without approval, and a replayed approval. The approved call in between is allowed. Explained in the [tool-permissions walkthrough](../docs/guides/tool-permissions.md). | One `DENIED` or `ALLOWED` line per case |
| [`agent-loop.mjs`](agent-loop.mjs) | How a model's tool calls go through the guard: one dispatcher function, a denial returned to the model as a tool result, and an action that waits for a reviewer. | One line per tool call |
| [`restart.mjs`](restart.mjs) | What the durable executor keeps across a restart (budgets, spend) and what must be reviewed again (an action that had not run). | Before-and-after lines |

## With a model provider

[`providers/`](providers) runs one protected ticket workflow in the request and response
shapes of two providers. The model's turns are scripted, so it runs offline; the
[provider workflow guide](../docs/guides/provider-ticket-workflow.md) walks through it and
shows where your own SDK client goes.

| File | Shows |
| --- | --- |
| [`providers/anthropic-messages.mjs`](providers/anthropic-messages.mjs) | The workflow in the Anthropic Messages tool-use format. |
| [`providers/openai-responses.mjs`](providers/openai-responses.mjs) | The same workflow in the OpenAI Responses function-call format. |
| [`providers/review-ticket.mjs`](providers/review-ticket.mjs) | The reviewer's side, in a terminal. |

The other files in `providers/` are shared by those three and are not entry points.

## Inventory and Agent Map (experimental)

These print one JSON document each. They are for people integrating the inventory observer
or Agent Map; skip them if you only use the guard.

| File | Shows |
| --- | --- |
| [`inventory-export.mjs`](inventory-export.mjs) | An executor publishing a read-only snapshot of its tasks, grants and tools. |
| [`inventory-manifest.mjs`](inventory-manifest.mjs) | A host manifest that declares which agent owns which task and resource. |
| [`agent-manifest.example.json`](agent-manifest.example.json) | The manifest as a file, for `loadInventoryManifestFile`. |
| [`agent-cartography.mjs`](agent-cartography.mjs) | A small synthetic company catalog, as Agent Map reads it. |

## Not examples

| File | What it is |
| --- | --- |
| [`cartography-pilot.mjs`](cartography-pilot.mjs) | A test host used by the collector's benchmark runner and by tests. Do not run it by hand. |
| [`safecall-executor.mjs`](safecall-executor.mjs) | An integration check with the separate `llm-safecall` package, which is not a dependency of this repository. It needs that package installed, or the path to its built entry file as an argument. |
