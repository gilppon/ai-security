# Production Deployment and Rollback Runbook

This runbook closes the release boundary for the existing Phase 0–12 control
plane. It does not introduce a new product phase or feature.

## Required release inputs

- [ ] Record the candidate as an **immutable image digest** (`repository@sha256:...`).
- [ ] Record the **previous image digest** before promotion.
- [ ] Attach the CI-generated SPDX JSON **SBOM** and image vulnerability result.
- [ ] Require a successful Phase 0–12, fault-matrix, R2-live, and container-release CI run.
- [ ] Verify that no unresolved fixable Critical or High image vulnerability exists.

## Production configuration

- [ ] Set `AI_SECURITY_ENVIRONMENT=production`.
- [ ] Set `AI_SECURITY_REQUIRE_VERIFIED_POLICY=true`.
- [ ] Inject signing and approval keys through the deployment platform's secret
      manager; never commit, echo, or place them in an image layer.
- [ ] Mount the approved policy store at an absolute path, read-only for the
      serving container, and set `AI_SECURITY_POLICY_STORE_PATH` to that path.
- [ ] Configure required R2 replication with the four `AI_SECURITY_R2_*`
      secrets and confirm the `audit/` bucket-lock rule is enabled.
- [ ] Preserve a read-only root filesystem, bounded no-exec tmpfs, non-root
      identity, dropped capabilities, `no-new-privileges`, PID/memory/CPU
      limits, and a loopback/private ingress boundary.

The repository `docker-compose.yml` is development-only. It is not an approved
production deployment manifest.

## Preflight

1. Pull the candidate by immutable digest and verify the observed digest.
2. Verify the signature and approval identities are current and not revoked.
3. Start one isolated candidate instance with production settings.
4. Confirm `/v1/health` succeeds and Docker reports the container healthy.
5. Confirm production startup fails when verified-policy inputs are withheld.
6. Confirm a policy-protected request produces the expected deterministic
   decision and fingerprint-only audit record.
7. Execute the required R2 replication probe and verify locked-object deletion
   is denied.

## Promotion

1. Promote the exact preflighted digest; never rebuild during promotion.
2. Use a canary or blue-green instance while the previous revision remains
   available.
3. Route test traffic and repeat the health, decision, audit, and R2 checks.
4. Shift production traffic only after every check succeeds.

## Rollback

Rollback immediately on failed health, denied audit durability, policy
activation failure, unexpected decision drift, or elevated error rate.

1. Stop promotion and route traffic to the **previous image digest**.
2. Do not roll back the monotonic policy store to an older version. If policy
   caused the incident, publish a newly approved higher-version correction.
3. Repeat `/v1/health`, deterministic decision, audit append, and R2 durability
   checks on the restored application revision.
4. Preserve the failed image digest, policy fingerprint, audit fingerprints,
   UTC timestamps, and sanitized CI links for incident review.

## Required evidence record

- Git commit and GitHub Actions run URL
- candidate and previous immutable image digests
- SBOM artifact identifier and vulnerability scan conclusion
- policy id fingerprint, version, signer/approver fingerprints
- health and smoke-test result
- R2 object fingerprint and lock-denial result
- operator, UTC deployment time, rollback decision, and final state

Never record raw prompts, policy source, signing keys, approval keys, R2
credentials, or audit payloads in release evidence.
