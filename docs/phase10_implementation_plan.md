# Phase 10 — Durable Audit

Status: **COMPLETE**. Local durability controls, the required immutable-replica
contract, and the Cloudflare R2 adapter are implemented and verified. The live
R2 write/idempotency/deletion-lock gate passed on 2026-09-10.

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

## External completion evidence

1. `tests/integration/test_r2_audit_replica_live.py` wrote a content-addressed
   object to the `ai-security` R2 bucket.
2. Repeating the same write returned the locked-object response and verified
   the existing payload byte-for-byte.
3. Deletion was rejected by the enabled seven-day `audit/` bucket-lock rule.
4. The successful live-test object remains external retention evidence.

The live gate is reproducible with `scripts/verify_phase10_r2.ps1`; credentials
are process-local, hidden during input, and removed after the test.

## Current verification

- Focused durable-audit tests cover 3-process concurrent writes, tampering,
  Windows ACLs, replica outage, WORM idempotency, rotation, and recovery.
- Full suite: `294 passed, 3 skipped` on Windows 11; the credential-gated live
  R2 test passed separately.
- Source distribution and wheel build successfully.
- Dependency audit reports no known vulnerabilities.
