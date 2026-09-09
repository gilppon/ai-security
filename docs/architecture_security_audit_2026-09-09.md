# AI Security Control Plane — Architecture / Security Audit

Audit date: 2026-09-09 (Asia/Seoul)

Scope: official architecture Phase 0–8 extraction, current-code mapping, Critical/High reproduction, and approved remediation verification.

## 1. Official Phase extraction

The authoritative source used was `AI Security Control Plane — Codex 개발 아키텍처 명세.md`, section 19 (`개발 단계`).

| Official Phase | Required modules/capabilities |
|---|---|
| 0 — Foundation | Project skeleton, config, logging, event model, decision model, risk model, tests |
| 1 — Security Core | SecurityEvent, SecurityDecision, RiskEngine, AISec Rule Engine, Audit Logger |
| 2 — Input Protection | Prompt Firewall, Jailbreak Detector, Encoding Detector, Normalization |
| 3 — Content Protection | RAG Firewall, Document Scanner, Hidden Content Scanner, Source Trust |
| 4 — Agent Protection | Tool Registry, Tool Firewall, Argument Validator, MCP Gateway, Plan Validator |
| 5 — Resource Protection | Filesystem Firewall, Network Firewall, Process Firewall, API Firewall |
| 6 — Secret / Output Security | Secret Engine, PII, Output Guard, Redaction |
| 7 — Runtime Protection | Session Monitoring, Behavior Engine, Correlation, Anomaly Detection |
| 8 — Red Team Regression | Probe Template, Scenario Runner, Expected Decision, Regression Score |

The architecture also defines the invariant pipeline:

`SecurityEvent -> Normalize -> Context -> Detect -> Risk -> Policy -> Decision -> Audit`

## 2. Current-code mapping

| Official Phase | Current implementation evidence | Assessment |
|---|---|---|
| 0 | `app/config.py`, `core/events/`, `core/decisions/`, `core/context/`, `core/risk/`, `telemetry/audit.py`, tests | Implemented |
| 1 | `core/pipeline.py`, `detection/parser.py`, `detection/engine.py`, `policy/engine.py`, `telemetry/audit.py` | Implemented |
| 2 | `input_security/prompt/`, `input_security/jailbreak/` | Implemented |
| 3 | `content_security/firewall.py`, `content_security/rag/`, `content_security/document/`, `content_security/source_trust/` | Implemented |
| 4 | `agent_security/tools/`, `agent_security/mcp/`, `agent_security/planner/`, `agent_security/chaining/` | Implemented |
| 5 | `resource_security/filesystem/`, `network/`, `process/`, `database/`, `api/` | Implemented; process isolation boundary remains conditional |
| 6 | `secret_detection/`, `output_security/` | Implemented |
| 7 | `runtime/monitor.py`, `runtime/sessions/`, `runtime/behavior/` | Implemented |
| 8 | `detection/redteam/`, `tests/integration/test_redteam_regression.py`, `tests/security/test_redteam_security.py` | Implemented |

Current code additionally contains post-Phase-8 work (`execution/sandbox/`, durable audit/policy lifecycle documents, and related controls). These are not added to the official Phase list and are tracked as extensions/boundaries, not new official phases.

## 3. Baseline verification

Command: `python -m pytest`

Result: **270 passed, 2 skipped** in 1.92 seconds.

The workspace is not a Git worktree (`git status` returned `fatal: not a git repository`), so no pre-audit commit/diff baseline was available. This report is therefore based on the filesystem state and executed checks.

## 4. Critical / High findings

### H-001 — OS isolation is applied after child process creation

Severity: **High**

Evidence: `execution/sandbox/executor.py` creates the child with `subprocess.Popen(...)` and only afterwards calls `isolation_backend.apply(process, ...)`. If `apply` fails, the child is killed, but it may have executed during the pre-isolation window. The default constructor also leaves OS isolation disabled unless `require_os_isolation=True`.

Reproduction (no source changes): a fake isolation backend observed a live child PID at its `apply` callback and then raised `RuntimeError`; the executor subsequently entered the isolation-failure path. Observed output included `backend_observed=(None, 39112, True)` where the first value is `process.poll()`.

Impact: an authorized process can perform work before the requested CPU/memory or other OS boundary is active. This violates fail-closed isolation when isolation is required.

### H-002 — Network authorization returns a hostname after DNS authorization

Severity: **High (conditional on a downstream network client)**

Evidence: `resource_security/network/firewall.py` verifies resolved addresses, but constructs `normalized_resource` as `https://{hostname}:{port}`. It also returns the resolved addresses separately rather than binding the authorized destination to one of them.

Reproduction (no source changes): with `rebind.example` resolving to `93.184.216.34`, authorization returned:

```text
decision=ALLOW
normalized_resource=https://rebind.example:443
resolved_addresses=('93.184.216.34',)
```

Impact: a later client-side DNS lookup can resolve a different, private, loopback, or metadata address after authorization. The current public API exposes authorization rather than HTTP execution, so exploitability depends on a downstream consumer using `normalized_resource`.

### H-003 — Production policy signature verification is opt-in rather than environment-enforced

Severity: **High (deployment/configuration control gap)**

Evidence: `app/config.py` defaults `require_verified_policy` to `False`, and `app/policy_startup.py` returns no verifier whenever that flag is false. `environment='production'` does not force the flag.

Reproduction (no source changes):

```text
Settings(environment='production') -> verifier_from_settings(...) == None
```

Impact: a production process can start without the verified-policy activation gate if the deployment omits `AI_SECURITY_REQUIRE_VERIFIED_POLICY=true`. This allows the policy lifecycle control to be bypassed by configuration omission.

## 5. Critical findings

No Critical vulnerability was confirmed by the executed checks. The audit did confirm default-deny behavior for unauthenticated tool/MCP/runtime API paths, private/metadata network destinations, filesystem traversal/sensitive paths, process shell arguments, and output/secret controls through the existing test suite.

## 6. Recommended approval order

1. Approve H-001 for design correction and add a regression test proving no process starts before required isolation is active.
2. Approve H-002 for destination binding: downstream execution must consume an authorized resolved address/pin, with redirect reauthorization preserved.
3. Approve H-003 for production startup policy: production must require verified policy configuration or fail closed.

## 7. Approved remediation and verification

The user approved H-001 through H-003. Only those findings were changed:

| Finding | Remediation | Verification |
|---|---|---|
| H-001 | Required Windows OS isolation creates the child suspended, binds it to a Job Object and capability-free AppContainer, and resumes it only after successful binding. Unsupported required controls still fail before execution. | Host tests verify CPU, memory, network, restricted child/descendant token, read-only workspace, minimal environment, and end-to-end SafeExecutor enforcement. |
| H-002 | Allowed network resources are normalized to the first verified public resolved address, preventing downstream hostname re-resolution through the authorization result. | Regression test expects `https://93.184.216.34:443`; private/mixed DNS tests remain passing. |
| H-003 | Production startup now raises unless verified policy is explicitly required and configured. | Regression test covers `Settings(environment="production")`. |

Post-remediation verification:

- Focused tests: **33 passed**.
- Full tests: **273 passed, 2 skipped**.
- Build: **sdist and wheel successfully built** with `python -m build`.
- Secret/risky-pattern scan: no new hardcoded credential, `shell=True`, unsafe YAML loader, or direct `eval`/`exec` pattern found in project source; the documented `shell=True` example remains only in the architecture specification.
