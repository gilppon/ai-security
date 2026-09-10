# Phase 10 Durable Audit — Pre-fix Audit

Date: 2026-09-10  
Status: Closed; local findings and external Cloudflare R2 WORM behavior verified

## Scope

`telemetry/audit.py`, append-only file behavior, integrity verification,
concurrent writers, local ownership, retention, and durable replication.

## Findings

| ID | Severity | Finding | Reproduction / evidence |
|---|---|---|---|
| P10-H-001 | High | Each sink caches its tail hash and uses only a process-local lock. Two writers can append sibling records with the same `previous_hash`, corrupting the chain. | Two independently constructed sinks wrote two valid lines; `verify()` raised `AuditIntegrityError: audit hash chain mismatch`. |
| P10-H-002 | High | A writer reads only the existing tail at startup and does not verify the complete chain before appending. It can extend an already tampered history. | `_read_tail_hash()` validates shape and length, not preceding links or hashes. |
| P10-H-003 | High | No durable replica contract exists. A local write can be reported as successful when a required immutable/WORM destination is unavailable. | `AuditSink` has only `write`; there is no required multi-destination acknowledgement policy. |
| P10-M-001 | Medium | File path checks occur at construction, while later opens follow the path again. Symlink/reparse replacement creates a time-of-check/time-of-use risk. | `resolve()` is retained, but every write calls `os.open(path, ...)` without no-follow/reparse validation. |
| P10-M-002 | Medium | A single `os.write` return value is ignored, so a partial append is not detected before the cached tail advances. | `write()` calls `os.write(fd, encoded)` once and unconditionally stores `record_hash`. |
| P10-M-003 | Medium | Owner-only ACL enforcement and verification are absent on Windows. | Mode `0o600` is requested at creation, but no Windows DACL is applied or inspected. |
| P10-M-004 | Medium | Rotation, retention, recovery manifests, and cross-segment verification are absent. | The sink owns one unbounded JSONL path and verifies only that file. |

## Remediation order

1. Cross-process exclusive locking and in-lock full-chain verification.
2. Complete-write enforcement and path identity/reparse checks.
3. Owner-only local ACL with a host-verifiable check.
4. Hash-linked segment rotation, retention manifest, and recovery verification.
5. Required durable replica adapter with fail-closed acknowledgement semantics.

No finding is considered closed until focused concurrency, tamper, ACL,
retention, recovery, and replica-failure tests pass.

## Remediation verification

- P10-H-001, P10-H-002: closed by cross-process locking and in-lock full-chain
  verification; 3 concurrent processes preserve one 30-record chain.
- P10-H-003: closed by required immutable replica acknowledgement and a live
  Cloudflare R2 test proving write, idempotent replay, and bucket-lock deletion
  denial beneath `audit/`.
- P10-M-001 through P10-M-004: closed by target revalidation, complete-write
  loops, owner-only Windows ACLs, and hash-linked retained segments with a
  verified recovery manifest.

## Completion evidence

- Date: 2026-09-10
- Provider: Cloudflare R2, private `ai-security` bucket
- Retention control: enabled seven-day Bucket Lock for prefix `audit/`
- Live gate: `tests/integration/test_r2_audit_replica_live.py` passed
- Credential handling: secure interactive input, process-only environment, and
  cleanup on completion
