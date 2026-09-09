# MCP Result Gateway Implementation Plan

## Scope

Add the missing MCP execution-result inspection path without adding a public
execution endpoint.

## Authorization binding

1. A successful MCP tool authorization issues a random, short-lived, one-time
   result capability.
2. The capability binds authorization event, verified agent, verified server,
   declared tool, and session.
3. Failed authorization never issues a capability.
4. Result inspection verifies trusted caller identities and atomically consumes
   the capability. Invalid, expired, replayed, or mismatched capabilities deny.

## Inspection pipeline

`MCP result -> capability/identity -> Content Firewall -> Output Guard -> Risk -> Policy -> Decision -> Audit`

- MCP result content is always external and untrusted.
- Content Firewall isolates prompt injection, hidden content, and RAG-style
  poison before context release.
- Output Guard blocks secrets, credentials, internal markers, and dangerous URLs
  before final release.
- Results expose released clean/sanitized text only. Denied raw text is never
  returned or written to audit.

## Boundaries

- No network call or tool execution is added.
- No raw result appears in capability state, events, or audit records.
- Result capability storage is in-memory, bounded, thread-safe, and replaceable.
- Output source is a trusted internal enum, not caller-controlled request data.

## Verification

- Capability issuance only on allowed MCP authorization.
- Clean result release, injection denial, secret denial, identity mismatch,
  expiry, replay, capacity failure, nested engine failure, and raw audit
  exclusion.
- Full pytest, package build, Compose validation, and focused security scans.
