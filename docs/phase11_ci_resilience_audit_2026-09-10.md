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
- Local verification after additional remediation: `305 passed, 3 skipped`;
  build and dependency audit pass.

Final closure remains gated on a successful GitHub-hosted workflow run.

## Post-deployment CI findings — approval required

The first GitHub-hosted run (`34463714748`) passed the complete fault matrix and
Phase 0–1, 3–5, 7–9, and 11 jobs. It exposed two additional High findings that
were not part of the pre-fix audit approval:

| ID | Severity | Finding | Reproduction / evidence |
|---|---|---|---|
| P11-H-004 | High | Phase-isolated Python 3.12 imports expose a circular dependency between `input_security.jailbreak.detector`, the eager `input_security.prompt` package initializer, and `input_security.prompt.firewall`. | GitHub Phase 2 failed; the exact Python 3.12 command reproduced `ImportError: cannot import name 'JailbreakDetector' from partially initialized module`. |
| P11-H-005 | High | The AppContainer integration cannot start the isolated Python 3.12 probe in the GitHub-equivalent runtime layout. | GitHub Phase 6 failed; two local Python 3.12 reproductions returned process exit `107` instead of the expected sandboxed success. Together with CI this reached the three-failure circuit breaker. |

The Phase 10 job failed once on GitHub but passed twice under the same local
Python 3.12 test command. It remains an unconfirmed transient or host-specific
failure and is not yet assigned a remediation finding.

Both findings received explicit additional approval on 2026-09-10.

- P11-H-004 is locally closed by deferring the `JailbreakDetector` import until
  `PromptFirewall` construction. Fresh-process import tests pass on Python 3.12
  and 3.14.
- P11-H-005 is locally closed without widening sandbox permissions. The native
  test is assigned to Phase 9 and runs from a short root-path Python 3.12 copy;
  the complete native-isolation group passed 12/12 in that layout.

Phase 11 remains incomplete until the updated GitHub workflow passes.
