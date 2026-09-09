# Phase 6 Implementation Plan

## Scope

Implement the architecture-defined Secret / Output Security phase:

1. Proprietary Secret Detection Engine
2. PII detection
3. Output Guard
4. Deterministic redaction
5. `POST /v1/security/output/scan`

Runtime behavior correlation belongs to Phase 7 and is intentionally excluded.

## Security invariants

- LLM output is untrusted and is never released without deterministic scanning.
- Detectors return only category, location, risk, length, and fingerprints; raw
  secrets and PII never enter findings, decisions, events, or audit logs.
- Secret classification combines proprietary pattern, entropy, context,
  location, and exposure scoring without copying third-party rule corpora.
- Private keys and production-output credentials are denied by policy.
- Redactable lower-risk data is replaced before release.
- Overlapping findings are merged deterministically so no partial secret remains.
- Any detector/redactor failure defaults to deny and releases no output.
- Clean output is explicitly allowed; an empty or malformed request is rejected
  by the input model.

## Implementation

### Secret Detection Engine

- Add bounded pattern detectors for API keys, Git tokens, cloud access keys,
  JWTs, private keys, database credentials, and generic credential assignments.
- Add Shannon entropy calculation as a supporting signal, not a standalone
  final decision.
- Classify findings and compute deterministic risk from category, entropy,
  verified location, and exposure context.
- Keep detector matches internal and expose only fingerprints and metadata.

### Output Guard

- Scan for secrets, PII, credential-bearing URLs, and internal control-plane
  markers.
- Convert findings into the shared Detect -> Risk -> Policy -> Decision chain.
- Redact selected spans with typed placeholders and deterministic overlap rules.
- Release original text only on ALLOW, redacted text only on SANITIZE/LOG, and
  no text on DENY or internal failure.

### API

- Add `POST /v1/security/output/scan` using a replaceable Output Guard
  dependency.
- Return decision, structured findings, fingerprints, lengths, and the permitted
  output only.

## Verification

- Unit tests for each secret category, entropy behavior, contextual risk,
  fingerprints, and false-positive boundaries.
- Unit tests for email, phone, and Luhn-valid payment-card PII.
- Redaction tests for adjacent and overlapping findings.
- Output Guard tests for clean allow, PII sanitize, secret deny, internal marker
  deny, failure default-deny, and absence of raw sensitive data in audit logs.
- API integration tests for clean, sanitized, and denied output.
- Full pytest, compile, wheel build, and secret-log bypass search.

## Boundaries

- This phase does not claim exhaustive credential or PII coverage.
- Runtime session monitoring, correlation, and anomaly detection remain Phase 7.
- No external security-project source or rule corpus is used.
