# Phase 12 — Policy Lifecycle Safety

Status: **COMPLETE** (2026-09-11)

## Implemented

- Canonical immutable `PolicyBundle`; identity, version, and complete rules are
  covered by both the content fingerprint and HMAC-SHA256 signature.
- Cross-process serialized policy history with strictly monotonic versions,
  policy-id switch denial, complete writes, fsync, and pre-resolution symlink
  rejection.
- Independently authenticated approvals bound to policy id, version, content
  fingerprint, and signer identity.
- Verified-only registry mode that permanently rejects unsigned publication.
- Fingerprint-only publication and activation audit events for both successful
  and denied outcomes.
- Production startup fail-closed for missing store, key material, approval,
  invalid signature, invalid history, or unavailable activation service.
- Multi-signer and multi-approver key maps with explicit revocation lists for
  bounded overlap and cutover rotation.
- Secret-wrapped signing and approval key configuration.
- One active immutable policy detector installed into FastAPI, CLI, prompt,
  content, tool, MCP, output, runtime, plan, filesystem, network, process,
  database, and API authorization paths.
- Policy detectors produce findings; `RiskEngine` calculates risk and
  `PolicyEngine` remains the final deterministic decision authority.
- Dedicated Phase 12 GitHub Actions regression matrix.

## Local verification

- Phase 12 focused regressions: `24 passed`.
- Python 3.12 complete suite: `320 passed, 3 skipped` (`323` collected),
  including the native Windows AppContainer test from the short-path runtime.
- Phase 11 fault matrix: 6/6 passed; p95 1 ms, max 1 ms.
- Source distribution and wheel build: passed.
- Dependency audit: no known vulnerabilities found.
- Hardcoded-secret and unsafe-shell scans: no new finding.

## Remote verification

- GitHub Actions `Security regression` run
  [34540595732](https://github.com/gilppon/ai-security/actions/runs/34540595732):
  **20/20 jobs succeeded**, including the Phase 12 policy-lifecycle matrix,
  native AppContainer enforcement, R2 live replication, and the fault matrix.
