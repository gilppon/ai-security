# Phase 11 CI Resilience and Evidence — Pre-fix Audit

Date: 2026-09-10  
Status: **GITHUB CI BLOCKED; ADDITIONAL APPROVAL REQUIRED**

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

Both findings received explicit additional approval on 2026-09-10.

- P11-H-004 is locally closed by deferring the `JailbreakDetector` import until
  `PromptFirewall` construction. Fresh-process import tests pass on Python 3.12
  and 3.14.
- P11-H-005 is locally closed without widening sandbox permissions. The native
  test is assigned to Phase 9 and runs from a short root-path Python 3.12 copy;
  the complete native-isolation group passed 12/12 in that layout.

## Repeated GitHub-hosted failures — approval required

Runs `34470177181` and `34470626831` both failed the updated Phase 9 and Phase
10 jobs while every other phase and the complete fault matrix passed. Together
with run `34463714748`, the underlying AppContainer failure and the Phase 10
failure have each reached the three-failure circuit breaker.

| ID | Severity | Finding | Reproduction / evidence |
|---|---|---|---|
| P11-H-005 | High | The approved short-path native-runtime remediation passes locally but does not close the AppContainer regression on `windows-latest`. | The original Phase 6 failure plus later Phase 9 failures. Split run `34472484173` proves `sandbox-core` passes and only `appcontainer-native` fails. |
| P11-H-006 | High | Phase 10 has a repeatable GitHub-hosted Windows regression that is not reproduced by the same Python 3.12 test group locally. | Phase 10 failed in three combined runs. Split run `34472484173` proves both R2 jobs pass and only `append-only` fails. |
| P11-M-003 | Medium | Sanitized per-target diagnostics are retained in the runner log but are not exposed by the unauthenticated GitHub check API, which reports only exit code 1. | Run `34470626831` check annotations contain `Process completed with exit code 1` without the safe failing-target message. |

No code remediation for P11-H-006 or P11-M-003 has been applied. The next-best
diagnostic is to write only the allowlisted failing test paths to the GitHub job
summary, then use that evidence to reproduce and prepare a separately reviewed
fix. P11-H-005 remains open despite its approved first remediation.

Run `34472484173` additionally split host-specific groups into allowlisted job
labels. This closes the public failure-localization gap in P11-M-003 without
publishing captured pytest output: Phase 9 resolves to `appcontainer-native`,
and Phase 10 resolves to `append-only`. The two High findings remain open.

Run `34472967163` narrowed P11-H-006 to
`test_append_only_sink_rejects_relative_and_symlink_paths`; every other
append-only group passed. Inspection confirmed that the constructor resolved
the candidate before checking `is_symlink()`, thereby discarding the link
identity. The approved fix checks the original candidate first and adds a
deterministic regression test for hosts where real symlink creation is denied.

The allowlisted P11-H-005 diagnostic reproduced locally as
`decision=LOG`, `reason_codes=PROCESS_NONZERO_EXIT`, `exit_code=107`, and
`marker_exists=False`. Python documents 107 as an invalid `pyvenv.cfg` result,
which is consistent with a virtual runtime whose base path is inaccessible from
the AppContainer. Remote confirmation is still required before changing the
runtime layout.

Run `34473584600` confirmed the remote failure occurs earlier than the local
virtual-runtime failure: `decision=DENY`, `reason_codes=UNKNOWN_SECURITY_STATE`,
`exit_code=none`, and `marker_exists=False`. GitHub currently maps
`windows-latest` to Windows Server 2025, while the experimental Win32 App
Isolation API used by the backend targets Windows 11. The approved remediation
moves only `appcontainer-native` to the generally available
`windows-11-arm` hosted runner; no test is skipped and no sandbox permission is
widened.

The Windows 11 run `34473968008` reached the API but failed closed with
`PROCESS_ISOLATION_FAILED`. To avoid exposing raw Windows errors while locating
the failing boundary, approved structured diagnostics now attach only a bounded
`isolation_failure_stage` code to the decision metadata and CI allowlist.

Phase 11 remains incomplete, and Phase 12 must not start, until an updated
GitHub workflow passes every job.
