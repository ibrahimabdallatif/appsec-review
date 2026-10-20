---
paths:
  - "**/*.{ts,tsx,js,jsx,mjs,cjs,py,go,cs,java,kt,rb,php,rs}"
  - "**/*.{yml,yaml,json,toml,md,txt,prompt,jinja,j2,hbs,mustache}"
detect:
  - "a manifest lists an LLM or agent SDK: openai, @anthropic-ai/sdk, anthropic, @google/genai, google-genai, @google/generative-ai, cohere, mistralai, @mistralai/mistralai, ollama, groq-sdk, together, ai (Vercel AI SDK), @ai-sdk/*, langchain, @langchain/*, langgraph, llamaindex, llama-index, haystack, semantic-kernel, Microsoft.SemanticKernel, Azure.AI.OpenAI, spring-ai, langchain4j, autogen, crewai, openai-agents, @openai/agents, dspy, transformers, vllm, litellm"
  - "MCP servers or clients: @modelcontextprotocol/sdk, mcp, fastmcp, modelcontextprotocol-*, .mcp.json or mcp.json files"
  - "vector stores: pinecone, @pinecone-database/*, weaviate, qdrant, chromadb, pgvector, milvus, faiss, lancedb"
---

# AI, LLM and agent features

OWASP Top 10 for LLM Applications 2025 (LLM01–LLM10), OWASP Top 10 for Agentic Applications 2026 (ASI01–ASI10),
OWASP A01/A05/A06:2025, API4/API5:2023. CWE-77, CWE-94, CWE-200, CWE-285, CWE-639, CWE-79, CWE-89, CWE-918,
CWE-502, CWE-770, CWE-1426, CWE-1427.

Load this file only when the repository's `detect` front matter matches (SKILL.md step 4): a manifest lists an LLM,
agent, MCP or vector-store package. It reviews code that builds prompts, calls models, exposes tools to a model,
stores agent memory or retrieves documents, and code that uses model output.

## How to judge findings here
- **The model is not a security boundary.** Any text in its context window can steer it: user input, retrieved
  documents, web pages, emails, tickets, tool output, other agents' messages. Instructions in the system prompt
  ("never reveal…", "only act for this user") are not a control. A finding needs a control that lives in code:
  authorization in the tool or downstream API, schema validation, an allow-list, a sandbox, a tenant filter in
  the query, or an approval bound to the exact call.
- Prompt injection alone is not the finding; what it can reach is. Report it at `critical` or `bug` only when
  injected text can drive a tool call, data access or output that crosses a boundary (another user or tenant,
  money, credentials, code execution, data leaving the system). A chatbot that can only answer the user who
  typed the prompt, with no private data and no tools, is `suggestion` at most.
- Name the injection source (which untrusted content reaches the context), the capability it reaches, and the
  missing code control.

## Dangerous capability combinations (LLM01, LLM06, ASI01)
- Flag one model context that combines all three of: **untrusted content**, **access to private data** (other
  tenants' or users' records, secrets, internal APIs) and **a way out or a way to change things** (outbound HTTP
  or fetch tools, email or message sending, write or delete APIs, code execution with network access, or
  rendering model output that can load attacker URLs such as Markdown images). Injected content can then read
  private data and send it out or act on it. (This combination is often called the "lethal trifecta".)
- Acceptable splits: a reader model with no tools that returns only schema-validated fields; a plan fixed before
  untrusted content is read; an egress allow-list on fetch and code tools; or human approval of the action.

## Tools and function calling (LLM06, ASI02, ASI03)
- Every tool must authorize **in its own code**, per call, for the end user and tenant the agent acts for. Flag
  tools that run with a service account or admin credential and trust ids or tenant values chosen by the model.
  (CWE-285, CWE-639)
- Flag tool arguments used without server-side schema validation: model-chosen URLs fetched without a host
  allow-list (SSRF, CWE-918), file paths without a base-directory check, SQL or shell strings built from
  arguments (CWE-89, CWE-77), and identifiers that are not checked against the caller's own objects.
- Read-only and mutating tools should be separate (different servers, namespaces or credentials). Flag a single
  tool or server that both reads untrusted content and performs writes.
- Flag fetch tools that follow redirects or resolve DNS without re-validating the host and address on every hop.
- Approvals must be bound to the exact call (tool plus a hash of its arguments) and show the concrete action,
  target and amount, not the model's summary. Flag "approve all", session-wide consent, and approvals that stay
  valid after the arguments change. Irreversible, costly, externally visible or cross-tenant actions need one.
- Metered or paid actions must re-check authorization and quota immediately before each call, not from an
  earlier cached check.

## MCP servers and clients (ASI02, ASI03, ASI04)
- MCP servers in this repository: every tool authenticates the **user** (delegated OAuth with narrow scopes, or
  the caller's own token) and authorizes per tenant. Flag servers that hold one broad shared credential for all
  callers, cross-tenant write tools, and HTTP transports without authentication or with permissive CORS.
- MCP clients and agent configs: flag third-party servers not pinned to a version or digest, servers whose tool
  descriptions come from an untrusted source (descriptions are prompt input), and tool output allowed to trigger
  calls to another server's tools without a policy check.
- Local stdio servers launched from config must not take their command or arguments from user-editable data.

## Retrieval, memory and vector stores (LLM04, LLM08, ASI06)
- Tenant and permission filters must be part of the retrieval query (metadata filter, namespace or index per
  tenant), not applied by the model or after retrieval. Flag searches without a tenant filter, and shared
  indexes keyed without tenant. (CWE-639)
- Embedded and indexed copies must follow the source document's permissions and deletion. Flag documents that
  stay retrievable after deletion or a permission change.
- Long-term agent memory written from untrusted content needs provenance (source, tenant, author) and must not
  later be read as trusted instructions or shared across users.

## Model output handling (LLM05)
- Model output is untrusted input to whatever uses it. Flag output rendered as HTML or Markdown without
  sanitisation (CWE-79), Markdown images or links to arbitrary hosts (a data-exfiltration channel), output
  passed to `eval`, `exec`, a shell, a template engine or a SQL string (CWE-94, CWE-77, CWE-89), and output
  parsed as JSON and used for authorization or money decisions without schema validation.
- Generated code run by the application needs a sandbox: container or microVM, no host mounts, no network by
  default, CPU, memory and time limits, a throwaway filesystem. (ASI05)

## Secrets, prompts and data in transit (LLM02, LLM07)
- Flag secrets, connection strings, other users' data or authorization rules placed in prompts or system
  prompts. Assume the system prompt can be extracted.
- Flag full prompts and completions containing personal or card data written to logs, analytics or third-party
  tracing (LangSmith, Langfuse, Helicone and similar) without redaction.
- Model-provider API keys must stay server-side. Flag keys in client bundles, mobile apps or `NEXT_PUBLIC_`/
  `VITE_`/`EXPO_PUBLIC_` variables, and client-side calls straight to a provider with a long-lived key.

## Model and plugin supply chain (LLM03, ASI04)
- Flag model weights or checkpoints loaded from pickle-based formats (`torch.load` without `weights_only=True`,
  `pickle`, `joblib` on downloaded files) and `trust_remote_code=True` on third-party models. Prefer
  safetensors. (CWE-502)
- Pin models, adapters and vector-index snapshots by version or hash; flag loads of "latest" from a public hub
  in production code.

## Cost and resource limits (LLM10, ASI08, ASI10)
- Flag model calls driven by unauthenticated or unthrottled input, missing per-user or per-tenant token and spend
  limits, unbounded agent loops (no step, depth, time or token cap), recursive agent spawning without a limit,
  and no kill switch. Charge these as abuse of a paid resource (API4, CWE-770).

Adapted in part from the agentic and LLM design guide in vasilyu1983/AI-Agents-public
(skills/universal/software-security-appsec, MIT License, copyright 2024-2026 Vasiliy Uvarov).
