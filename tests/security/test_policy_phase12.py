import json
from datetime import UTC, datetime

import pytest
from pydantic import SecretStr

from app.config import Settings
from app.policy_startup import activation_service_from_settings, verifiers_from_settings
from core.decisions.actions import DecisionAction
from core.decisions.reasons import ReasonCode
from detection.models import RuleAction
from policy.activation import PolicyActivationService
from policy.lifecycle import PolicyBundleRegistry, parse_policy_bundle
from policy.signing import PolicySignatureVerifier, sign_policy_bundle
from policy.storage import (
    DurablePolicyBundleStore,
    PolicyApproval,
    PolicyApprovalVerifier,
    PolicyStoreError,
    PolicyVersionRollbackError,
    create_approval,
)
from telemetry.audit import InMemoryAuditSink, StructuredAuditLogger


SOURCE = """
id: ASEC-POLICY-PHASE12
title: Phase 12 policy
category: core
severity: info
when:
  event_type: prompt.scan
match:
  source: user
risk:
  score: 100
actions: [deny, audit]
"""

SIGNER_KEY = b"s" * 32
APPROVER_KEY = b"a" * 32


def _signed(version: int = 1, *, policy_id: str = "phase12-policy"):
    bundle = parse_policy_bundle(policy_id, version, SOURCE)
    return sign_policy_bundle(bundle, signer_id="release-key", key=SIGNER_KEY)


def _approval(signed):
    return create_approval(
        "approval-1",
        "security-approver",
        signed,
        key=APPROVER_KEY,
    )


def _activate(registry: PolicyBundleRegistry, store: DurablePolicyBundleStore):
    return PolicyActivationService(registry, store).activate_verified(
        PolicySignatureVerifier({"release-key": SIGNER_KEY}),
        PolicyApprovalVerifier({"security-approver": APPROVER_KEY}),
    )


def test_signature_binds_canonical_rule_content() -> None:
    signed = _signed()
    changed_rule = signed.bundle.rules[0].model_copy(
        update={"actions": (RuleAction.ALLOW, RuleAction.AUDIT)}
    )
    tampered_bundle = signed.bundle.model_copy(update={"rules": (changed_rule,)})
    tampered = signed.model_copy(update={"bundle": tampered_bundle})

    assert not PolicySignatureVerifier({"release-key": SIGNER_KEY}).verify(tampered)


def test_store_rejects_rollback_across_registry_restart(tmp_path) -> None:
    store = DurablePolicyBundleStore(tmp_path / "policy.jsonl")
    version_two = _signed(2)
    store.append(version_two, _approval(version_two))

    version_one = _signed(1)
    with pytest.raises(PolicyVersionRollbackError):
        store.append(version_one, _approval(version_one))

    decision, active = _activate(PolicyBundleRegistry(), store)
    assert decision.decision is DecisionAction.ALLOW
    assert active is not None and active.version == 2


def test_approval_is_authenticated_and_bound_to_complete_bundle(tmp_path) -> None:
    approved = _signed(1, policy_id="approved-policy")
    approval = _approval(approved)
    other = _signed(99, policy_id="different-policy")
    store = DurablePolicyBundleStore(tmp_path / "policy.jsonl")

    with pytest.raises(ValueError, match="approval does not match"):
        store.append(other, approval)

    forged = PolicyApproval(
        approval_id="forged-approval",
        approver_id="security-approver",
        policy_id=approved.bundle.policy_id,
        policy_version=approved.bundle.version,
        bundle_fingerprint=approved.bundle.content_fingerprint,
        signer_id=approved.signer_id,
        approved_at=datetime.now(UTC),
        signature="0" * 64,
    )
    store.append(approved, forged)
    decision, active = _activate(PolicyBundleRegistry(), store)

    assert decision.decision is DecisionAction.DENY
    assert decision.reason_codes == (ReasonCode.POLICY_APPROVAL_INVALID,)
    assert active is None


def test_verified_registry_rejects_unsigned_publication(tmp_path) -> None:
    registry = PolicyBundleRegistry()
    store = DurablePolicyBundleStore(tmp_path / "policy.jsonl")
    signed = _signed()
    store.append(signed, _approval(signed))
    assert _activate(registry, store)[0].decision is DecisionAction.ALLOW

    unsigned = parse_policy_bundle("phase12-policy", 2, SOURCE.replace("Phase 12", "Unsigned"))
    result = registry.publish(unsigned)

    assert result.decision.decision is DecisionAction.DENY
    assert result.decision.reason_codes == (ReasonCode.POLICY_SIGNATURE_REQUIRED,)
    assert registry.current() is not None and registry.current().version == 1

    signed_only = _signed(2)
    signed_result = registry.publish_signed(
        signed_only,
        PolicySignatureVerifier({"release-key": SIGNER_KEY}),
    )
    assert signed_result.decision.reason_codes == (ReasonCode.POLICY_APPROVAL_REQUIRED,)
    assert registry.current() is not None and registry.current().version == 1


def test_activation_denial_is_audited_without_raw_identity_or_signature(tmp_path) -> None:
    signed = _signed()
    store = DurablePolicyBundleStore(tmp_path / "policy.jsonl")
    forged = _approval(signed).model_copy(update={"signature": "0" * 64})
    store.append(signed, forged)
    sink = InMemoryAuditSink()
    service = PolicyActivationService(
        PolicyBundleRegistry(),
        store,
        audit_logger=StructuredAuditLogger(sink),
    )

    decision, active = service.activate_verified(
        PolicySignatureVerifier({"release-key": SIGNER_KEY}),
        PolicyApprovalVerifier({"security-approver": APPROVER_KEY}),
    )

    assert decision.reason_codes == (ReasonCode.POLICY_APPROVAL_INVALID,)
    assert active is None
    assert len(sink.records) == 1
    record = json.loads(sink.records[0])
    assert record["event_type"] == "policy.bundle.activate"
    assert record["decision"] == "DENY"
    assert signed.signer_id not in sink.records[0]
    assert signed.signature not in sink.records[0]
    assert "security-approver" not in sink.records[0]


def test_activation_rejects_signer_mismatch_and_audits_it(tmp_path) -> None:
    signed = _signed()
    store = DurablePolicyBundleStore(tmp_path / "policy.jsonl")
    store.append(signed, _approval(signed))
    sink = InMemoryAuditSink()
    service = PolicyActivationService(
        PolicyBundleRegistry(),
        store,
        audit_logger=StructuredAuditLogger(sink),
    )

    decision, active = service.activate_verified(
        PolicySignatureVerifier({"other-key": b"x" * 32}),
        PolicyApprovalVerifier({"security-approver": APPROVER_KEY}),
    )

    assert decision.reason_codes == (ReasonCode.POLICY_SIGNATURE_INVALID,)
    assert active is None
    assert len(sink.records) == 1


def test_successful_activation_audit_contains_fingerprints_not_raw_policy(tmp_path) -> None:
    signed = _signed()
    store = DurablePolicyBundleStore(tmp_path / "policy.jsonl")
    store.append(signed, _approval(signed))
    sink = InMemoryAuditSink()
    logger = StructuredAuditLogger(sink)
    service = PolicyActivationService(
        PolicyBundleRegistry(audit_logger=logger),
        store,
        audit_logger=logger,
    )

    decision, active = service.activate_verified(
        PolicySignatureVerifier({"release-key": SIGNER_KEY}),
        PolicyApprovalVerifier({"security-approver": APPROVER_KEY}),
    )

    assert decision.decision is DecisionAction.ALLOW
    assert active is not None
    serialized = "".join(sink.records)
    assert len(sink.records) == 2
    assert "Phase 12 policy" not in serialized
    assert SOURCE.strip() not in serialized
    assert signed.signature not in serialized


def test_signer_rotation_supports_overlap_then_revocation() -> None:
    old = sign_policy_bundle(_signed().bundle, signer_id="old-key", key=b"o" * 32)
    new = sign_policy_bundle(_signed(2).bundle, signer_id="new-key", key=b"n" * 32)
    overlap = PolicySignatureVerifier({"old-key": b"o" * 32, "new-key": b"n" * 32})

    assert overlap.verify(old)
    assert overlap.verify(new)

    cutover = PolicySignatureVerifier(
        {"old-key": b"o" * 32, "new-key": b"n" * 32},
        revoked_signer_ids={"old-key"},
    )
    assert not cutover.verify(old)
    assert cutover.verify(new)


def test_startup_key_maps_support_rotation_and_revocation() -> None:
    settings = Settings(
        require_verified_policy=True,
        policy_signing_keys_json=json.dumps({
            "old-key": (b"o" * 32).hex(),
            "new-key": (b"n" * 32).hex(),
        }),
        policy_approval_keys_json=json.dumps({
            "security-approver": APPROVER_KEY.hex(),
        }),
        policy_revoked_signer_ids=("old-key",),
    )
    verifiers = verifiers_from_settings(settings)
    assert verifiers is not None
    old = sign_policy_bundle(_signed().bundle, signer_id="old-key", key=b"o" * 32)
    new = sign_policy_bundle(_signed(2).bundle, signer_id="new-key", key=b"n" * 32)

    assert not verifiers.signatures.verify(old)
    assert verifiers.signatures.verify(new)
    assert verifiers.approvals.verify(_approval(_signed()))


def test_store_checks_symlink_before_resolution(monkeypatch, tmp_path) -> None:
    candidate = tmp_path / "policy-link.jsonl"
    calls: list[str] = []

    def fake_is_symlink(path):
        calls.append(str(path))
        return path == candidate

    monkeypatch.setattr(type(candidate), "is_symlink", fake_is_symlink)

    with pytest.raises(ValueError, match="symlink"):
        DurablePolicyBundleStore(candidate)
    assert calls == [str(candidate)]


def test_startup_store_failure_is_audited_without_raw_path() -> None:
    raw_path = "relative-sensitive-policy-store.jsonl"
    sink = InMemoryAuditSink()
    logger = StructuredAuditLogger(sink)

    with pytest.raises(RuntimeError, match="verified policy store unavailable"):
        activation_service_from_settings(
            Settings(require_verified_policy=True, policy_store_path=raw_path),
            audit_logger=logger,
        )

    assert len(sink.records) == 1
    record = json.loads(sink.records[0])
    assert record["event_type"] == "policy.bundle.activate"
    assert record["decision"] == "DENY"
    assert record["reason_codes"] == [ReasonCode.POLICY_STORE_INVALID.value]
    assert record["metadata"]["event_data"] == {
        "activation_state": "denied",
        "store_state": "unavailable",
    }
    assert raw_path not in sink.records[0]


def test_read_only_policy_store_loads_without_mutation_or_sidecar(tmp_path) -> None:
    path = tmp_path / "policy.jsonl"
    signed = _signed()
    writable = DurablePolicyBundleStore(path)
    writable.append(signed, _approval(signed))
    lock_path = tmp_path / ".policy.jsonl.lock"
    lock_path.unlink()
    path.chmod(0o444)

    read_only = DurablePolicyBundleStore(path, read_only=True)
    loaded = read_only.load_latest()

    assert loaded is not None and loaded[0] == signed
    assert not lock_path.exists()
    with pytest.raises(PolicyStoreError, match="read-only"):
        read_only.append(signed, _approval(signed))


def test_settings_redact_policy_keys_from_repr() -> None:
    settings = Settings(
        policy_signing_key_hex=SecretStr("11" * 32),
        policy_approval_key_hex=SecretStr("22" * 32),
    )

    rendered = repr(settings)
    assert "11" * 32 not in rendered
    assert "22" * 32 not in rendered
    assert "**********" in rendered
