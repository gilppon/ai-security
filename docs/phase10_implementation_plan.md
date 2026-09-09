# Phase 10 — Durable Audit

Status: **IN PROGRESS**. All local durability controls and the required
immutable-replica contract are implemented and tested. A real remote WORM
service and external retention-anchor verification remain completion blockers.

## Data path

`SecurityEvent -> StructuredAuditLogger -> RequiredReplicatedAuditSink -> immutable replica acknowledgement -> local hash chain`

The caller receives success only after every required replica acknowledges.
Replica failure raises `AuditDurabilityError` before the local sink reports a
commit, preserving fail-closed behavior for security-sensitive callers.

## Implemented

- Cross-process sidecar locking for each local audit chain.
- Full-chain verification while holding the writer lock before every append.
- Rejection of writes after existing-history tampering.
- Complete-write loops; cached tail hashes were removed.
- Target identity/symlink revalidation at verification and append time.
- Owner-only local file permissions, including removal of inherited Windows ACLs.
- Content-addressed, put-once directory WORM adapter suitable for an immutable
  local path or remotely mounted storage.
- Required replica coordinator that fails closed on rejection or outage.
- Multi-process, ACL, tamper, idempotency, and replica-outage tests.
- Hash-linked segment rotation with bounded retention and an integrity-protected
  recovery anchor manifest.
- Cross-segment restore verification and a recovery runbook.

## Remaining completion work

1. Selection and integration test of a real remote immutable/WORM provider.
2. Store and verify the retention anchor outside the writable host.

Phase 10 must not be marked complete until these two items have reproducible
evidence.

## Current verification

- Focused durable-audit tests cover 3-process concurrent writes, tampering,
  Windows ACLs, replica outage, WORM idempotency, rotation, and recovery.
- Full suite: `286 passed, 2 skipped` on Windows 11.
- Source distribution and wheel build successfully.
- Dependency audit reports no known vulnerabilities.
