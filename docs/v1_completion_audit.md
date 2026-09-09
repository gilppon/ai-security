# V1 Completion Audit

Status: **V1 COMPLETE**. This document distinguishes verified V1 implementation
from explicit deployment boundaries; passing tests alone is not used as proof.

## Non-negotiable controls

| Requirement | Evidence | Status |
|---|---|---|
| Default deny / least privilege | `PolicyEngine`, identity-aware Tool/MCP/API/DB/runtime controls | Verified |
| LLM output untrusted | `OutputGuard` scans before release | Verified |
| External content untrusted | `ContentFirewall` defaults source trust to unknown | Verified |
| Deterministic final decisions | Risk and Policy engines own decisions; no LLM dependency | Verified |
| Structured reason codes | `SecurityDecision` requires non-empty `ReasonCode` values | Verified |
| Events and audit | Control paths create `SecurityEvent` and structured JSON audit records | Verified by security tests |
| Replaceable modules | Constructors accept protocol/engine/logger implementations | Verified for implemented modules |
| Tool/network/filesystem mediation | Tool Firewall delegates resource capabilities to their firewalls | Verified by integration tests |
| Safe process invocation | Exact argv, capability consumption, `shell=False`, bounded output/timeout | Verified |
| Resolved resource authorization | Filesystem and network tests cover canonical paths and resolved IPs | Verified |
| No raw secret logging | Redaction/fingerprint tests across controls and CLI | Verified |
| Security-sensitive tests | Unit, integration, security, and regression suites | Verified |

## Development phases

| Phase | Required capability | Status |
|---|---|---|
| 0 | Skeleton, config, logging, event/decision/risk models, tests | Complete |
| 1 | SecurityEvent, SecurityDecision, Risk, AISec rules, audit | Complete |
| 2 | Prompt, jailbreak, encoding, normalization | Complete |
| 3 | RAG/content, document/hidden-content scan, source trust | Complete |
| 4 | Tool Registry/Firewall, argument validation, MCP, Plan Validator | Complete |
| 5 | Filesystem, network, process, database, API firewalls | Complete |
| 6 | Secret/PII/output/redaction | Complete |
| 7 | Session, behavior, correlation, anomaly rules | Complete |
| 8 | Probe templates, runner, expected decisions, regression scores | Complete |

## MVP checklist

Prompt Firewall, RAG Firewall, Risk Engine, AISec Rule Engine, Policy Engine,
Tool Firewall, MCP Gateway, Filesystem Firewall, Network Firewall, Secret
Detector, Output Guard, audit, FastAPI, and tests exist with focused coverage.
The previously missing CLI is now implemented as the packaged `python -m app`
entry point and accepts raw scan content through stdin only.

## Explicit deployment boundary

**Executor isolation:** timeout, output bound, minimal environment, workspace,
   exact argv, and one-time capabilities exist. Phase 9A now provides a replaceable
   Windows Job Object backend for CPU-time and memory ceilings, but it is opt-in
   (`require_os_isolation=True`) until host capability checks are deployed. Network
   isolation and full restricted-token/workspace hardening are still deployment
   boundaries; the executor must fail closed when those controls are required.

MCP execution results now require a short-lived, one-time capability bound to the
successful authorization event and verified identities. Content Firewall and
Output Guard both run before release; injection, secret, failure, replay,
expiry, and mismatch paths fail closed.

Empty future-oriented directory placeholders (`artifact_security`,
`intelligence`, `dashboard`, extended telemetry) are not in the V1 checklist or
phased deliverables and are not treated as current completion evidence.

## Minimum attack-scenario evidence

- Prompt/system/role/Unicode/Base64 attacks: prompt unit, security, and API tests.
- Indirect/RAG/hidden HTML attacks: content unit, security, and API tests.
- Traversal/SSH/AWS/.env access: Filesystem Firewall security tests.
- localhost/private/metadata/DNS/redirect SSRF: Network Firewall security tests.
- shell flags/command injection/capability replay: Process Firewall tests.
- unauthorized MCP/scope/description/result attacks: MCP security tests.
- secrets/private keys/JWT: Secret Detector and Output Guard tests.
- loops/flood/repeated denial: Plan Chain Policy and Runtime anomaly tests.

## Final verification evidence

- `244 passed, 1 skipped`; the skip is the existing Windows symlink-privilege
  case, not a disabled security test.
- All eight specified FastAPI paths are present.
- Wheel and source distribution build successfully and include all V1 modules.
- Docker Compose configuration validates.
- Focused direct-execution and secret scans find no new bypass or hardcoded
  credential in the added planner, regression, CLI, or MCP result modules.
