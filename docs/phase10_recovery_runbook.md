# Phase 10 Audit Recovery Runbook

## Trigger

Run this procedure after `AuditIntegrityError`, an unexpected segment gap,
replica rejection, host loss, or retention-manifest mismatch.

## Containment

1. Stop security-sensitive ALLOW operations; audit durability is fail-closed.
2. Do not edit, truncate, rename, or re-chain the affected audit files.
3. Preserve the audit directory and replica object metadata as evidence.
4. Record host, UTC time, failing segment name, and fingerprints only. Never
   copy raw secrets or payloads into the incident record.

## Verification

1. Run `SegmentedAuditFileSink.verify()` against a read-only copy.
2. Verify every retained segment's local hash chain.
3. Verify each segment header links to the preceding segment tail or the
   retention anchor.
4. Compare every content-addressed record with the immutable replica object of
   the same SHA-256 identifier.
5. Compare the local retention anchor with the externally stored anchor.

## Restore

1. Create a new owner-only audit directory; never restore over the suspect one.
2. Restore immutable objects in sequence into new hash-linked segments.
3. Verify the complete reconstructed chain and record count.
4. Atomically configure the application to use the verified directory.
5. Keep the suspect directory quarantined until incident review closes.

## Return to service

Resume security-sensitive operations only when local verification, immutable
replica comparison, external anchor verification, and a test audit write all
succeed. Any ambiguous state remains DENY.

## Cloudflare R2 live verification

Supply `AI_SECURITY_R2_ENDPOINT`, `AI_SECURITY_R2_BUCKET`,
`AI_SECURITY_R2_ACCESS_KEY_ID`, and `AI_SECURITY_R2_SECRET_ACCESS_KEY` only in
the invoking process environment. Run:

`python -m pytest tests/integration/test_r2_audit_replica_live.py -q`

On Windows, `scripts/verify_phase10_r2.ps1` prompts for both credential values
without echoing them and removes all four variables when the test exits.

The gate passes only when the content-addressed write is idempotent and the
enabled bucket-lock rule rejects deletion beneath `audit/`.
