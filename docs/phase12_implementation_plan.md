# Phase 12 — Policy Lifecycle Safety

## Implemented

- Immutable parsed `PolicyBundle` with content fingerprint.
- Monotonic version registry; rollback and policy-id switches are denied.
- Publish decisions emit structured audit events with fingerprints only.
- Registry and parser are independently replaceable from `PolicyEngine`.
- HMAC-SHA256 signed bundle verification with constant-time comparison.
- Invalid signatures are denied and audited by fingerprint only.
- Durable append-only signed bundle storage with approval binding.
- Startup-style activation gate requiring a valid signature and approval.
- FastAPI startup hook that fails closed when verified policy is required.

## Remaining
