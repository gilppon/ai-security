# Phase 3 — Content Protection Plan

## Scope

Implement deterministic security processing for external documents and RAG content. No remote fetching, file access, or LLM invocation is included.

## Pipeline

`Content submission -> SecurityEvent -> Normalize -> Hidden/Unicode/Instruction detection -> Source trust -> Risk -> Policy -> Decision -> Audit -> Isolated sanitized envelope`

## Controls

1. Require content and source types; callers cannot self-assign trust.
2. Treat API-submitted content as untrusted by server policy.
3. Detect HTML comments, hidden elements, active tags, Unicode controls, mixed scripts, indirect instructions, and RAG poison markers.
4. Use standard-library parsing and bounded Pydantic inputs; no executable HTML or external fetch.
5. Remove hidden/active content and unsafe Unicode format characters during sanitization.
6. Release sanitized content only for `ALLOW`, `LOG`, or `SANITIZE`; isolate all other decisions.
7. Store only content fingerprints, sizes, structured findings, and decisions in audit data.

## Validation

- Clean text, HTML, Markdown, and RAG documents.
- Indirect prompt injection and poisoned RAG content.
- Hidden HTML comments/elements, scripts, zero-width and bidi controls, mixed scripts.
- Unknown source, caller trust spoofing, blank/oversized payloads, fail-closed behavior.
- Context isolation, raw-content audit exclusion, API contract, full regression suite, compile and security scans.
