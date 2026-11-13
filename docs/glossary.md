# Glossary

The words Agent Guard uses, in the order you meet them.

| Term | Meaning |
| --- | --- |
| **Agent** | A program that lets a language model choose and call tools to get work done. |
| **Host** | Your trusted application code: the part that creates the guard, registers tools, creates tasks and collects approvals. The model is not part of the host. |
| **The guard** | The core package, `@shieldaai/agent-guard`. It runs inside the host process and decides whether a call may run. Its state is in memory. |
| **The executor** | The `@shieldaai/agent-guard-executor` package: the same checks, with state kept in an encrypted file (the ledger) so it survives restarts, and a token for each task. |
| **Tool** | One operation the agent may ask for, such as "read a ticket" or "send an email". You register it with a `resolve` function (which resource does this call touch?) and an `execute` function (do it). |
| **Fingerprint** | A hash of a tool's definition. You approve a tool by its fingerprint; if the definition changes, the fingerprint changes and the tool is refused until you approve it again. |
| **Tool changes** | `toolChanges(name)`: what differs between a tool's current definition and the one last approved, one entry per changed field, for a reviewer to read before approving again. It covers the definition, not the tool's code. |
| **Change hint** | An automatic mark on a changed field that often matters, such as new instruction-like text or a loosened schema. A heuristic for the reviewer: never a verdict, and never a block. |
| **Tool approval** | `approveTool(name, fingerprint)`: your code accepts a tool's definition. Done once per definition. It never allows a specific action. |
| **Task** | One piece of work for an agent, created by the host, with its own grants, tenant, principal and budget. |
| **Task handle** | The object the host gets back from `createTask`. Only that object carries the task's authority; a copy with the same ID does not. |
| **Grant** | Permission for a task to use one tool on a list of resources, for example `delete-ticket` on `ticket:42`. Anything not granted is refused. `*` is an explicit "any resource". |
| **Resource** | The thing a call acts on, named by an ID your application defines (`ticket:42`, an account, a file). |
| **Tenant** | The customer or organization a task belongs to. A call whose resource belongs to another tenant is refused. |
| **Principal** | Who the task acts for: a user, an operator or a named agent. Recorded in every decision. |
| **Recipient** | Where an outbound call sends data. External sends go only to recipients the task lists. |
| **Budget** | Limits on a task: how many calls, how many at once, how much cost, and a deadline. |
| **Prepare / execute** | The two steps of every call. `prepare` checks and freezes the action; `execute` re-checks and runs it. An action runs at most once. |
| **Action approval** | `approve(action, …)`: a person allows one prepared action. It is tied to that exact action, works once and expires. |
| **Delegation** | Creating a child task from a parent. The child can only have less: fewer resources, a smaller budget, an earlier or equal deadline. Revoking the parent revokes the child. |
| **Task family** | A task and all tasks created from it. Sensitivity and the outside-content mark are shared by the whole family. |
| **Sensitive** | A mark your `resolve` function sets when a call reads private data. After that, the family cannot send anything outside. |
| **Outside content** | Text that people outside your trust boundary can write: email, web pages, customer tickets, results from third-party tools. In the API the mark is called `untrusted`. Tools you label `readsUntrusted` set it; tools can be set to need approval, or be refused, once it is set. |
| **Revocation** | Ending a task's authority at once. Calls in progress are asked to stop; new calls are refused. |
| **Unknown outcome** | A call that started but whose result was lost (a crash, a timeout). The executor holds it for a person to check and never repeats it. |
| **Receipt** | The executor's record of what happened to one action. |
| **Reconcile** | An operator records, with a reference, whether an unknown outcome actually succeeded or failed. |
| **Ledger** | The executor's encrypted SQLite file holding tasks, approvals, budgets and receipts. |
| **Rollback witness** | A second small file, kept separately, that lets the executor notice that an old copy of the ledger was restored. |
| **Model Context Protocol (MCP)** | An open protocol through which an agent's host connects to tool servers. The MCP adapter puts those tools behind the guard. |
| **Descriptor digest** | A hash of an MCP tool's advertised definition that stays the same across connections. The guard's `operationChanges()` uses it to say whether the server changed a tool since it was approved. |
| **Quarantine** | The MCP adapter's state after something changed or went wrong: every tool from that connection is unavailable until you refresh and approve again. |
| **Sandbox** | The executor's optional Docker profile for running code you do not trust: no network, no host credentials. |
| **Governed memory** | The executor's memory tools: each entry records where it came from and can be quarantined or rolled back. |
| **Inventory / observer** | A read-only export of which tasks, tools and grants an executor has, polled by the collector (experimental). |
| **Host manifest** | A reviewed file in which a person declares the agents that exist, their owners and what they connect to. Agent Map lists only declared agents. |
| **Agent Map** | The read-only inventory service and viewer built on those exports (experimental). |
| **Dangerous three** | Agent Map's flag for an agent with a task that can read private data, read outside content and send data out. Elsewhere this combination is called the "lethal trifecta". |
| **Cartography** | The open-source graph tool the Python collector uses to load inventory into Neo4j. |
