# Phase 7 Implementation Plan

## Scope

Implement deterministic runtime protection:

1. Runtime event collection
2. Bounded session monitoring
3. Server-owned behavior profiles
4. Rule-based anomaly detection
5. Sequence correlation
6. Runtime event and session inspection APIs

The runtime path remains:

`SecurityEvent -> Context -> Detect -> Risk -> Policy -> Decision -> Audit`

## Security invariants

- Only a trusted integration may supply a verified agent identity.
- Public request bodies cannot assert agent identity, trust, timestamps, risk, or
  final decisions.
- Unverified runtime events are denied, audited, and never added to a session.
- Missing behavior profiles and session ownership mismatches default to deny.
- Session state is bounded by maximum sessions, events per session, and idle TTL.
- Raw prompts, paths, URLs, commands, tool arguments, and output are not accepted.
  Runtime events use semantic activity types and precomputed fingerprints.
- Session inspection returns counts and reason codes, never target fingerprints
  or raw event data.
- Every ingestion and inspection produces its own SecurityEvent and audit record.
- All critical anomaly decisions are deterministic; no LLM or statistical model
  participates in authorization.

## Deterministic rules

- Activity outside the server-owned agent profile
- Event-rate burst within a fixed window
- Repeated blocked/failed actions
- Excessive distinct target fan-out
- Blocked prompt followed by tool/process/network activity
- File access followed by outbound network activity

Rules operate on the current bounded session plus the candidate event. Findings
are converted to the shared Risk and Policy engines with structured reason codes.

## APIs

- `POST /v1/security/events`
- `GET /v1/security/sessions/{session_id}`

Until authentication middleware supplies a verified identity through a trusted
dependency, both public endpoints default to deny and disclose no session state.

## Verification

- Unit tests for profile validation, bounded storage, TTL, and ownership.
- Rule tests for each anomaly and benign activity.
- Tests proving rejected events do not poison session state.
- Tests proving summaries contain no target fingerprints or raw content.
- API tests proving public endpoints default to deny.
- Full pytest, compile, wheel build, Docker Compose validation, and sensitive
  telemetry/logging search.

## Boundaries

- Statistical baselines and machine-learning anomaly models are explicitly out
  of scope; the architecture specifies rule-based detection first.
- Authentication middleware and durable distributed session storage remain
  replaceable deployment integrations.
- No third-party security-project source or rule corpus is used.
