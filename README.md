# AI Security Control Plane

Proprietary defensive control plane for deterministic authorization of AI-system actions.

Current scope: Phase 0–8: security core, prompt/content protection, Tool Firewall,
MCP Gateway, filesystem/network/process/database/API authorization, a
token-gated Safe Executor, Secret Detection Engine, PII detection, deterministic
redaction, Output Guard, deterministic runtime behavior monitoring, and an
offline red-team regression harness.

```text
SecurityEvent -> Normalize -> Context -> Detect -> Risk -> Policy -> Decision -> Audit
```

Process execution is internal only. It accepts an opaque, short-lived,
single-use Process Firewall capability and invokes an exact executable with an
argument vector and `shell=False`. Database authorization accepts structured
query intent rather than raw SQL. API authorization must also pass the Network
Firewall. No public process, database, or HTTP execution endpoint is provided.

## Run

```powershell
python -m pytest
python -m uvicorn app.main:app --reload
```

CLI scans read untrusted content from standard input so raw prompts, documents,
and model output do not appear in process arguments:

```powershell
Get-Content .\prompt.txt -Raw | python -m app scan-prompt
Get-Content .\document.md -Raw | python -m app scan-content --content-type markdown --source-type rag_document
Get-Content .\model-output.txt -Raw | python -m app scan-output
```

The CLI exits with code `0` only for `ALLOW`, `LOG`, or `SANITIZE`; denied,
invalid, and failed operations exit with code `2` and a structured reason code.

See `AI Security Control Plane — Codex 개발 아키텍처 명세.md` for product architecture.

## Implemented API

- `GET /v1/health`
- `POST /v1/security/prompt/scan`
- `POST /v1/security/content/scan`
- `POST /v1/security/tool/authorize`
- `POST /v1/security/mcp/authorize`
- `POST /v1/security/output/scan`
- `POST /v1/security/events`
- `GET /v1/security/sessions/{session_id}`

Prompt responses contain decisions, structured findings, lengths, and fingerprints. Raw prompt content is never echoed or written to audit records.

Content responses release text only inside a provenance-bearing sanitized context envelope. Untrusted callers cannot assign source trust, and denied content is never released to an LLM context.

Tool and MCP endpoints perform authorization only. Public calls default to deny until a trusted authentication integration supplies a verified agent identity. No tool execution exists in this phase.

LLM-proposed multi-tool plans can be preflighted with `PlanValidator`. It checks
server-owned tool definitions, agent grants, argument schemas, repeated-call
loops, and file/database-to-network/API confused-deputy chains. A passing plan
never authorizes execution; every actual step must still pass Tool Firewall and
its resource firewall.

Authorized MCP calls receive a short-lived, one-time result capability bound to
the verified agent, server, tool, session, and authorization event. MCP results
must consume that capability and pass Content Firewall plus Output Guard before
clean or deterministically sanitized text can be released. Result capabilities
and denied raw content are never written to audit records.

Output responses release clean text or deterministically redacted PII only.
Secrets, sensitive credential URLs, internal policy markers, and security-engine
failures are blocked. Audit records contain fingerprints and metadata, never raw
output or detected values.

Runtime monitoring records bounded per-session activity metadata and detects
policy violations, event/denial bursts, target fanout, blocked-prompt bypass,
and file-to-network sequences. Profiles and caller identity are server-owned;
public runtime calls default to deny until trusted authentication is integrated.
Session inspection returns aggregate counts only, never raw targets or content.

The Phase 8 regression harness runs strict, server-owned probe suites against
explicitly registered in-process control evaluators. It reports deterministic
pass and block rates for prompt injection, RAG poisoning, MCP escalation,
secret leakage, and tool abuse. Missing or failing evaluators fail closed, and
reports/audit records contain probe fingerprints rather than raw probe content.
