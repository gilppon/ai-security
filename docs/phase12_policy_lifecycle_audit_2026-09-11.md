# Phase 12 Policy Lifecycle Safety — Pre-fix Audit

Audit date: 2026-09-11 (Asia/Seoul)

Status: **CLOSED — APPROVED REMEDIATION VERIFIED**

Scope: extract the Phase 12 requirements, map the current implementation,
reproduce Critical/High failures, and record the proposed remediation boundary.
No Phase 12 source code was modified during this audit.

## 1. Authoritative Phase 12 scope

The architecture completion plan defines Phase 12 as **Production Policy
Lifecycle** with these requirements:

- production must require a verified policy;
- signing keys and signer identities must support managed rotation;
- approvals must bind to the intended policy and versions must be monotonic;
- policy-store failure, signature failure, and approval mismatch must fail closed
  during startup;
- activation and rejection must be connected to the audit chain;
- private signing material and raw policy secrets must not enter logs; and
- rollback and signer-mismatch regressions must pass.

The invariant remains:

`SecurityEvent -> Normalize -> Context -> Detect -> Risk -> Policy -> Decision -> Audit`

## 2. Current-code mapping

| Required capability | Current evidence | Assessment |
|---|---|---|
| Immutable bundle and parser | `policy/lifecycle.py` | Present, but the stored fingerprint is trusted instead of recomputed |
| Signature creation and verification | `policy/signing.py` | Present, but the signature binds only policy id, version, and a caller-supplied fingerprint |
| Version registry | `PolicyBundleRegistry` | In-memory monotonic check only |
| Approval and durable store | `policy/storage.py` | JSONL append exists; approval is not authenticated and binds only content fingerprint |
| Startup activation | `policy/activation.py`, `app/policy_startup.py`, `app/bootstrap.py` | Production fails closed when configuration or activation fails |
| Runtime enforcement | API dependencies and firewall constructors | Active bundle is not consumed by request-time detectors or policy engines |
| Audit integration | Registry publication/verification events | Publication is audited; activation failure and approval decisions are not |
| Signer rotation | verifier accepts a key map; application settings build one key | Production rotation protocol and regression evidence are absent |
| Existing tests | five focused policy test files | 11 tests pass, but they do not cover the failures below |

## 3. Baseline verification

Focused command:

```text
python -m pytest -q tests/security/test_policy_lifecycle.py \
  tests/security/test_policy_signing.py \
  tests/security/test_policy_activation.py \
  tests/unit/test_policy_startup.py \
  tests/integration/test_policy_startup_gate.py
```

Result: **11 passed**.

The passing baseline does not establish Phase 12 completion because the test
suite omits canonical-content binding, runtime installation, durable rollback,
approval authenticity, signed-only publication, activation-denial auditing,
and signer rotation.

## 4. Confirmed Critical findings

### P12-C-001 — Policy rule tampering preserves a valid signature

`policy/signing.py` signs the tuple `(policy_id, version,
content_fingerprint)`. `PolicyBundle` accepts `content_fingerprint` as ordinary
input and does not recompute it from `rules` during model validation. A stored
record can therefore keep the signed fingerprint and signature while replacing
the actual rules.

Reproduction used a valid signed/approved bundle, changed its serialized rule
action from `allow` to `deny`, retained the original fingerprint and signature,
and loaded it through the production activation path:

```json
{"signature_valid_after_rule_tamper":true,"activation_decision":"ALLOW","activated_actions":["deny"]}
```

Impact: storage tampering can modify production policy semantics without being
detected by signature verification. The signature currently authenticates a
claim about content, not the content itself.

### P12-C-002 — Activated policy is disconnected from runtime enforcement

The activation service stores a bundle in `PolicyBundleRegistry`, but no API,
firewall, `DetectionEngine`, or `PolicyEngine` reads that registry. API
dependencies construct independent firewall and policy-engine instances.

Reproduction activated a signed production policy whose matching prompt rule
requested `deny`, then scanned a matching normal prompt through the FastAPI
endpoint:

```json
{"activated_actions":["deny","audit"],"runtime_prompt_decision":"ALLOW"}
```

Impact: successful startup activation does not change request-time security
decisions. The production lifecycle gate is operationally inert.

## 5. Confirmed High findings

### P12-H-001 — Restart permits rollback to an older signed policy

The monotonic version floor exists only in a registry instance. The store
returns the last JSONL record without validating history, and a fresh registry
has no durable minimum version.

Reproduction appended an approved version 2 and then an approved version 1,
simulated restart with a new registry, and activated the store:

```json
{"activation_decision":"ALLOW","activated_version":1,"expected_min_version":2}
```

Impact: replacing or extending the store with an older legitimately signed
bundle can reactivate a vulnerable policy after restart.

### P12-H-002 — Approval is not bound to policy identity or version

`PolicyApproval` contains only the rule-content fingerprint. It does not bind
`policy_id`, `version`, `signer_id`, or the complete signed artifact, and it has
no independently verifiable approver authentication.

Reproduction reused an approval created for `approved-policy@1` with a signed
`different-policy@99` bundle containing the same rule content:

```json
{"approval_created_for":"approved-policy@1","activation_decision":"ALLOW","activated":"different-policy@99","shared_content_fingerprint":true}
```

Impact: approval records can be replayed across policy identities and versions;
the current startup gate cannot prove that the activated artifact was the one
approved.

### P12-H-003 — Registry permits unsigned publication after verified startup

`PolicyBundleRegistry.publish()` is a public mutation path that performs no
signature or approval verification. The activation service itself calls this
unsigned method after doing its own checks, leaving no registry-level enforced
mode.

Reproduction published signed version 1 and then directly published unsigned
version 2:

```json
{"signed_v1":"ALLOW","unsigned_v2":"ALLOW","current_version":2}
```

Impact: any runtime component with registry access can replace an activated
policy without passing the verified lifecycle controls.

### P12-H-004 — Activation denials are not audited

`PolicyActivationService` returns denial decisions directly for missing
approval, approval mismatch, invalid signature, and invalid store state. It has
no audit logger and does not emit a `SecurityEvent` for these decisions.

Reproduction activated a bundle with a mismatched verifier key while the
registry used an in-memory audit sink:

```json
{"decision":"DENY","reason_codes":["POLICY_SIGNATURE_INVALID"],"audit_records":0}
```

Impact: production startup can be denied without the mandatory decision audit
record, preventing reliable incident reconstruction.

### P12-H-005 — Production signer rotation is not implemented

`PolicySignatureVerifier` can hold multiple keys when constructed directly,
but application settings accept only one signer and one shared HMAC key. There
is no rotation state, overlap/revocation rule, signer transition approval, or
startup regression proving old/new signer behavior.

Impact: the explicit Phase 12 rotation requirement and signer-mismatch
completion gate cannot be demonstrated. Emergency rotation risks either an
availability outage or indefinite trust in a compromised signer.

## 6. Additional Medium findings

### P12-M-001 — Policy-store symlink validation occurs after resolution

`DurablePolicyBundleStore` resolves the path before checking `is_symlink()`, so
an existing link is converted to its target before validation. The local Windows
account could not create a file symlink (`WinError 1314`), so host-level exploit
reproduction was unavailable; the control-flow defect is confirmed by source
inspection and matches the previously corrected append-only audit-path defect.

### P12-M-002 — Signing key configuration is represented as plain text

`Settings.policy_signing_key_hex` is a normal string rather than a secret type.
No current project logger was found printing it, but accidental settings
serialization or exception diagnostics could expose the key.

## 7. Proposed remediation boundary

Only the findings explicitly approved by the user will be changed.

1. Sign canonical policy content and recompute/validate the fingerprint at every
   trust boundary.
2. Install one immutable verified policy snapshot into request-time detection
   and policy evaluation before startup succeeds.
3. Persist and validate monotonic policy history across restart.
4. Authenticate approvals and bind them to policy id, version, content
   fingerprint, and signer identity.
5. Remove or seal unsigned registry mutation when verified mode is active.
6. Emit fingerprint-only audit events for every activation outcome, including
   failures.
7. Define bounded signer rotation and revocation semantics and test both old/new
   signer transitions.
8. Correct the symlink check and protect signing-key representation.

## 8. Required verification after approval

- tampered rules fail signature/fingerprint validation;
- an activated deny policy changes the corresponding runtime decision;
- rollback remains denied after registry/process restart;
- forged or cross-policy approval reuse is denied;
- verified mode exposes no unsigned publication path;
- activation success and every denial produce secret-safe audit records;
- signer mismatch, overlap, cutover, and revocation tests pass;
- focused Phase 12 tests, the complete Phase 0–12 regression suite, fault
  matrix, build, dependency audit, and GitHub CI all pass.

## 9. Gate decision

Phase 12 is marked **COMPLETE**. The approved remediation is locally verified,
and GitHub Actions run `34540595732` passed all 20 Phase 0–12 jobs.

## 10. Approval and remediation record

The user approved all nine findings on 2026-09-11. Only the approved Phase 12
scope was changed.

| Finding | Implemented remediation | Local regression evidence |
|---|---|---|
| P12-C-001 | Fingerprints cover policy identity, version, and canonical rule content; signatures cover the complete canonical bundle; verification independently checks fingerprint integrity. | Rule mutation with a retained fingerprint/signature is rejected. |
| P12-C-002 | `ActivePolicyDetector` supplies active bundle matches as findings before risk and policy evaluation across FastAPI, CLI, and security enforcement modules. | A signed production deny rule changes `/v1/security/prompt/scan` and CLI decisions to DENY. |
| P12-H-001 | The durable store validates the complete history and rejects non-increasing versions and policy-id switches under a cross-process lock. | Version 1 cannot be appended or activated after version 2. |
| P12-H-002 | HMAC-authenticated approval records bind approval id, approver, policy id, version, content fingerprint, and signer. | Forged signatures and cross-policy/version approval reuse are denied. |
| P12-H-003 | Activation permanently seals its registry; unsigned and signature-only publication paths cannot bypass authenticated approval. | Signed v1 remains active after attempted unsigned and unapproved signed v2 publication. |
| P12-H-004 | Every activation result, including store construction and history failures, emits a `policy.bundle.activate` event containing only bounded state and fingerprints. | Invalid store path, approval, and signer mismatch produce auditable DENY records without raw paths, identities, signatures, or policy source. |
| P12-H-005 | Secret-wrapped JSON key maps support old/new signer overlap and explicit signer/approver revocation. | Overlap accepts both signers; cutover rejects the revoked old signer and accepts the new signer. |
| P12-M-001 | The policy path is checked for symlinks before resolution and again before access; no-follow flags are used where available. | Deterministic call-order regression passes. |
| P12-M-002 | Signing and approval key fields and rotation maps use Pydantic `SecretStr`. | Settings representation contains redaction markers and no raw keys. |

## 11. Local post-remediation verification

- Phase 12 focused tests: **24 passed**.
- Complete Python 3.12 suite: **320 passed, 3 skipped** from **323 collected**;
  failures and errors: **0**.
- Native Windows AppContainer regression: passed using the dedicated short-path
  Python 3.12 runtime.
- Phase 11 fault matrix: **6/6 passed**, p95 **1 ms**, max **1 ms**.
- Package build: source distribution and wheel succeeded.
- Dependency audit: no known vulnerabilities found.
- Security pattern scan: no new hardcoded credential or `shell=True` use.

Final closure evidence: GitHub Actions `Security regression` run
[34540595732](https://github.com/gilppon/ai-security/actions/runs/34540595732)
completed successfully with **20/20 jobs passed**.
