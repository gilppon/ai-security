# Phase 10 — Durable Append-Only Audit Store

## Implemented

- Replaceable `AuditSink` implementation using JSONL.
- SHA-256 hash chain with previous-record binding.
- Atomic append under a process lock, optional `fsync`, and bounded record size.
- Absolute, non-symlink path requirement with restrictive file mode.
- Verification API that fails closed on malformed or tampered records.
- Existing redaction and `StructuredAuditLogger` contracts remain unchanged.

## Boundaries

- This is a local append-only store, not a remote WORM service.
- Multi-process locking and OS ACL hardening belong to deployment integration.
- No raw secret or credential value is added to the envelope.
