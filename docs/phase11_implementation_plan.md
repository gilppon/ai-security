# Phase 11 — Deterministic Resilience Evaluation

Status: **LOCAL IMPLEMENTATION VERIFIED; GITHUB CI EVIDENCE PENDING**

## Implemented

- Server-owned, bounded fault injector with explicit pipeline stages.
- Optional pipeline fault hook; disabled by default.
- Regression test proving injected failure produces deterministic DENY,
  `UNKNOWN_SECURITY_STATE`, and an audit record.
- Bounded resilience scenario runner with expected decisions and latency budgets.
- Server-owned timeout, audit-sink, and resource-exhaustion scenario catalog.
- Deterministic summary with pass/fail counts, p95, and max latency.

## CI implementation

- Six-stage executable fault matrix covering normalize, context, detect, risk,
  policy, and audit.
- Deterministic non-zero process exit on decision, reason-code, scenario budget,
  p95, or max-latency failure.
- Allowlisted evidence schema that excludes decision metadata, matched rules,
  payloads, prompts, outputs, and secrets.
- Per-run p95/max history uploaded as a 30-day GitHub Actions artifact.
- Phase 0–11 regression matrix with every current test file assigned.
- Pinned action SHAs, read-only repository permissions, and captured pytest
  output that is neither printed nor uploaded.

## Verification

- Focused Phase 11 tests: `16 passed`.
- Full local suite: `305 passed, 3 skipped` on Windows 11 with native isolation.
- Python 3.12 full suite passes with the host-native marker excluded; the same
  native-isolation tests pass from the dedicated root-path Python 3.12 runtime.
- Local six-stage matrix: 6/6 passed; p95 1 ms, max 1 ms.
- Package build and dependency audit passed.
- Phase 11 is not complete until the committed workflow passes on GitHub.
