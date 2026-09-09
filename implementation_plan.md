# Phase 0–1 Implementation Plan

## Scope

Implement only the Foundation and Security Core described in the architecture specification. Prompt, content, tool, MCP, resource, execution, secret, runtime, and output firewalls remain out of scope except for replaceable package boundaries.

## Plan

1. Create the documented project skeleton and top-level `AGENTS.md`.
2. Add minimal Python project metadata for Python 3.12+, FastAPI, Pydantic v2, PyYAML, and pytest.
3. Implement immutable, validated `SecurityEvent`, `SecurityContext`, `RiskScore`, and `SecurityDecision` models.
4. Implement a deterministic risk engine with bounded additive scoring and structured contributions.
5. Implement a strict proprietary AISec YAML rule parser and deterministic evaluator. Unknown or invalid security state fails closed.
6. Implement structured reason codes and an append-only structured JSON audit logger that redacts sensitive values.
7. Compose the pipeline as `SecurityEvent -> Normalize -> Context -> Detect -> Risk -> Policy -> Decision -> Audit` with independently replaceable protocols.
8. Add a FastAPI application with `GET /v1/health` only.

## Validation

- Unit tests for model validation, default-deny behavior, risk bounds, deterministic rule matching, malformed rules, and audit redaction.
- Integration tests for the core pipeline and health endpoint.
- Run focused tests first, then the complete pytest suite.
- Run configured type/lint checks if the project metadata includes them.
- Scan source and fixtures for hardcoded credential-like values and unsafe process execution patterns.

## Risks and Boundaries

- No third-party security source code or rule corpus will be copied.
- No LLM-produced value will become a final decision.
- No tool, network, filesystem, or process execution capability will be implemented in this phase.
- No raw credentials, event payload secrets, or full sensitive resources will be written to audit logs.
- Dependencies stay limited to the technology explicitly named in the specification.
