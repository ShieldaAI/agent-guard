# Standards and further reading

This page relates Agent Guard's controls to published frameworks, and lists a few
articles that explain the problem well. It is a map for orientation. It is not a claim of
compliance with any of them.

For the risk-by-risk view against the OWASP agentic list, see
[Risks and how Agent Guard handles them](risks.md).

## Controls and where they appear in the frameworks

| Agent Guard control | OWASP Agentic Top 10 (2026) | OWASP LLM Top 10 (2025) | Read more |
| --- | --- | --- | --- |
| A task can only use the tools and resources it was granted | ASI02, ASI03 | LLM06:2025 Excessive Agency | [OWASP agentic top 10][asi] |
| Tenant check on every call | ASI03 | | [OWASP agentic top 10][asi] |
| A person approves one exact action, once, before it expires | ASI09, ASI02 | LLM06:2025 Excessive Agency | [OWASP agentic top 10][asi] |
| Budgets and deadlines per task and its parents | ASI08, ASI02 | LLM10:2025 Unbounded Consumption | [OWASP LLM top 10][llm] |
| A sub-task only gets less than its parent; revocation follows | ASI03, ASI10 | LLM06:2025 Excessive Agency | [OpenID Foundation paper][openid] |
| Tool definitions are approved by fingerprint; MCP definitions can be pinned by digest | ASI04 | LLM03:2025 Supply Chain | [OWASP MCP cheat sheet][mcp-cheat] |
| After reading sensitive data, a task cannot send outside | ASI01, ASI02 | LLM01:2025 Prompt Injection, LLM02:2025 Sensitive Information Disclosure | [The lethal trifecta][trifecta] |
| After reading outside content, chosen tools need approval or are refused | ASI01 | LLM01:2025 Prompt Injection | [Agents Rule of Two][rule-of-two] |
| Configured secret values are refused in outbound arguments | ASI02 | LLM02:2025 Sensitive Information Disclosure | [OWASP LLM top 10][llm] |
| Optional Docker profile with no network for untrusted code | ASI05 | LLM05:2025 Improper Output Handling | [OWASP agentic top 10][asi] |
| Governed memory with origin, quarantine and rollback | ASI06 | LLM04:2025 Data and Model Poisoning | [OWASP agentic top 10][asi] |
| Read-only inventory that flags private data + outside content + sending out | ASI10 | LLM06:2025 Excessive Agency | [The lethal trifecta][trifecta] |

OWASP numbers its lists per edition, so always quote the year with the identifier
(`LLM06:2025`).

## Frameworks

- **[OWASP Top 10 for Agentic Applications 2026][asi]** (OWASP GenAI Security Project,
  December 2025). The ten risks ASI01 to ASI10 that [risks.md](risks.md) follows.
- **[OWASP Top 10 for LLM Applications 2025][llm]**. The broader list for applications
  built on language models. Excessive Agency (LLM06:2025) is the entry closest to what
  Agent Guard addresses.
- **[OWASP MCP Security Cheat Sheet][mcp-cheat]**. Practical controls for Model Context
  Protocol clients and servers. It recommends pinning reviewed tool definitions by hash
  and reviewing them again when they change, which is what `descriptorDigest` is for.
- **[OWASP MCP Top 10][mcp-top10]** (beta). Ten MCP-specific risks, including tool
  poisoning (MCP03:2025) and insufficient authentication and authorization (MCP07:2025).
- **[MITRE ATLAS][atlas]**. A catalog of techniques used against AI systems. The entries
  most relevant here are LLM Prompt Injection (AML.T0051), its Indirect sub-technique
  (AML.T0051.001) and AI Agent Tool Invocation (AML.T0053).
- **[NIST AI 600-1][nist-genai]**, the Generative AI Profile of the NIST AI Risk Management
  Framework (July 2024). A risk-management vocabulary an organization can place these
  controls in.
- **[Identity Management for Agentic AI][openid]** (OpenID Foundation, October 2025). On
  delegated authority, narrowing scope along a chain of agents, and revocation.

## Articles that explain the problem

- Simon Willison, **[The lethal trifecta for AI agents: private data, untrusted content,
  and external communication][trifecta]** (June 2025). Why an agent that has all three is
  open to data theft. Agent Map's "dangerous three" flag is this combination.
- Meta, **[Agents Rule of Two: A Practical Approach to AI Agent Security][rule-of-two]**
  (October 2025). An agent should hold at most two of: untrustworthy input, access to
  sensitive data, and the ability to change state or communicate outside.
- UK National Cyber Security Centre, **[Prompt injection is not SQL injection (it may be
  worse)][ncsc]** (December 2025). Why injection cannot simply be filtered out, and why
  limiting what the system can do matters.
- Greshake et al., **[Not what you've signed up for: Compromising Real-World
  LLM-Integrated Applications with Indirect Prompt Injection][greshake]** (2023). The
  paper that described instructions hidden in content an agent reads.
- Invariant Labs, **[MCP Security Notification: Tool Poisoning Attacks][invariant]**
  (April 2025). Instructions hidden in MCP tool descriptions, and servers that change a
  description after approval.
- Debenedetti et al., **[Defeating Prompt Injections by Design][camel]** (2025), and
  Beurer-Kellner et al., **[Design Patterns for Securing LLM Agents against Prompt
  Injections][patterns]** (2025). Research on designs that separate what an agent is
  allowed to do from the content it reads.

[asi]: https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/
[llm]: https://genai.owasp.org/llm-top-10/
[mcp-cheat]: https://cheatsheetseries.owasp.org/cheatsheets/MCP_Security_Cheat_Sheet.html
[mcp-top10]: https://owasp.org/www-project-mcp-top-10/
[atlas]: https://atlas.mitre.org/
[nist-genai]: https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.600-1.pdf
[openid]: https://openid.net/wp-content/uploads/2025/10/Identity-Management-for-Agentic-AI.pdf
[trifecta]: https://simonwillison.net/2025/Jun/16/the-lethal-trifecta/
[rule-of-two]: https://ai.meta.com/blog/practical-ai-agent-security/
[ncsc]: https://www.ncsc.gov.uk/blog-post/prompt-injection-is-not-sql-injection
[greshake]: https://arxiv.org/abs/2302.12173
[invariant]: https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks
[camel]: https://arxiv.org/abs/2503.18813
[patterns]: https://arxiv.org/abs/2506.08837
