# Phase 11 CI Resilience and Evidence — Pre-fix Audit

Date: 2026-09-10  
Status: **REMEDIATED LOCALLY; GITHUB CI EVIDENCE PENDING**

## Official architecture scope

- Complete fault-matrix CI job.
- Security-regression jobs separated by architecture phase.
- Historical p95 and maximum latency evidence.
- Artifact policy that excludes raw payloads, prompts, outputs, and secrets.
- CI failure when a latency regression threshold is exceeded.

## Current code mapping

| Architecture requirement | Current implementation | Gap |
|---|---|---|
| Fault injection stages | `evaluation/faults.py::FaultStage` defines normalize, context, detect, risk, policy, and audit | The default catalog covers only context, risk, and audit |
| Scenario execution | `evaluation/scenarios.py::ResilienceRunner` records decisions and elapsed time | No executable full-matrix command or CI exit contract |
| Summary evidence | `ResilienceSummary` calculates total, pass/fail, p95, and max | No history file, baseline comparison, or artifact schema |
| Fail-closed pipeline test | `tests/integration/test_fault_pipeline.py` injects one detect-stage failure | One stage is tested; it is not the complete matrix |
| CI workflows | None | `.github/workflows` does not exist |
| Artifact redaction | Audit logging has redaction, but resilience result serialization does not use it | Arbitrary decision metadata is emitted unchanged |

## Findings

| ID | Severity | Finding | Reproduction / evidence |
|---|---|---|---|
| P11-C-001 | Critical | No CI workflow exists, so fault, phase-regression, evidence, and latency gates cannot prevent a merge. | Read-only check returned `MISSING:.github/workflows`. |
| P11-H-001 | High | The advertised fault matrix is incomplete and not wired to real pipeline operations. Normalize, detect, and policy are absent from the default catalog; the integration test injects detect only. | Catalog inspection returned `catalog_stages=['audit','context','risk']` and `missing_stages=['detect','normalize','policy']`. |
| P11-H-002 | High | Resilience artifacts can contain raw prompt and secret values through `SecurityDecision.metadata`. | Serializing a valid `ResilienceResult` reproduced both `RAW-PROMPT-MARKER` and `RAW-SECRET-MARKER` unchanged. |
| P11-H-003 | High | A latency budget violation does not fail a process or job. It only sets `passed=False`; callers can exit successfully without checking it. | A 21 ms operation with a 1 ms budget printed `passed=False` followed by `process_continued_without_failure` and exited zero. |
| P11-M-001 | Medium | p95/max values are calculated in memory but no bounded historical baseline is stored or compared. | No benchmark-history writer, reader, or regression comparator exists under `evaluation/`, `tests/`, or CI. |
| P11-M-002 | Medium | Failed-stage and reason-code data exists in models but has no minimal, sanitized evidence artifact contract. | `ResilienceResult` embeds the complete decision object; there is no allowlisted evidence model. |

## Existing verification

- Focused current tests: `6 passed`.
- The tests prove bounded injection primitives, one fail-closed pipeline path,
  summary math, and duplicate-ID rejection.
- They do not satisfy the Phase 11 CI completion criteria above.

## Proposed remediation order

1. Define an allowlisted evidence model and prove raw-value exclusion.
2. Build a real six-stage fault-matrix command with deterministic non-zero exit
   on decision, reason-code, or latency failure.
3. Add bounded benchmark-history comparison for p95 and max latency.
4. Add phase-regression and fault-matrix GitHub Actions jobs with sanitized
   artifacts only.
5. Run focused tests, the complete suite, package build, dependency audit, and
   a workflow syntax/security review.

At audit time, no remediation was authorized. The findings below were changed
only after explicit user approval.

## Approved remediation verification

All six findings were approved on 2026-09-10.

- P11-C-001: a pinned, least-privilege GitHub Actions workflow now defines
  Phase 0–11 regression and full fault-matrix jobs.
- P11-H-001: all six `FaultStage` values execute against a real
  `SecurityPipeline` and produce deterministic fail-closed decisions.
- P11-H-002 and P11-M-002: an allowlisted evidence model excludes complete
  decision metadata and raw values; explicit leak tests pass.
- P11-H-003 and P11-M-001: scenario, p95, and max thresholds control the CLI
  exit code, while sanitized per-run evidence provides 30-day CI history.
- Local verification: `304 passed, 3 skipped`; build and dependency audit pass.

Final closure remains gated on a successful GitHub-hosted workflow run.
