# Phase 2 — Input Protection Plan

## Scope

Implement deterministic prompt inspection only. Detectors emit findings; they cannot make final security decisions. Existing `RiskEngine` and `PolicyEngine` remain the sole decision path.

## Data flow

`SecurityEvent -> Prompt Normalize -> Prompt Detect -> SecurityContext -> Risk -> Policy -> SecurityDecision -> Audit`

## Components

1. Bounded request/result and finding models.
2. NFKC and zero-width-aware prompt normalizer.
3. Deterministic prompt rule detector.
4. Base64/hex encoding detector with validated decoding and printable-content checks.
5. Obfuscation detector for control characters, mixed-script tokens, and separator abuse.
6. Jailbreak detector using proprietary, minimal deterministic patterns.
7. Prompt firewall orchestrator with default-deny and fail-closed handling.
8. `POST /v1/security/prompt/scan` with filtered response model.

## Validation

- Normal prompts and false-positive examples.
- System override, system prompt extraction, role override, jailbreak, tool manipulation, and exfiltration.
- Base64-like attacks, harmless identifiers, zero-width text, mixed scripts, separator abuse, blank/oversized inputs.
- Decision/audit integration, raw-prompt non-disclosure, detector failure behavior, and HTTP contract.

## Boundaries

- No semantic LLM classifier.
- No external security code or rule corpus.
- No tool execution, filesystem access, network access, or process execution.
- No raw prompt in events, decisions, API responses, or audit logs.
