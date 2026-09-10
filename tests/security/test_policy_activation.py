from core.decisions.actions import DecisionAction
from core.decisions.reasons import ReasonCode
from policy.activation import PolicyActivationService
from policy.lifecycle import PolicyBundleRegistry, parse_policy_bundle
from policy.signing import PolicySignatureVerifier, sign_policy_bundle
from policy.storage import DurablePolicyBundleStore, PolicyApprovalVerifier, create_approval


SOURCE = """
id: ASEC-POLICY-ACTIVE
title: Activate health policy
category: core
severity: info
when:
  event_type: system.health.check
match:
  source: internal
risk:
  score: 0
actions: [allow, audit]
"""

APPROVER_KEY = b"a" * 32


def test_activation_requires_verified_signed_approved_bundle(tmp_path) -> None:
    key = b"z" * 32
    bundle = parse_policy_bundle("active-policy", 1, SOURCE)
    signed = sign_policy_bundle(bundle, signer_id="release-key", key=key)
    store = DurablePolicyBundleStore(tmp_path / "policy.jsonl")
    store.append(signed, create_approval(
        "approval-1", "approver-1", signed, key=APPROVER_KEY
    ))
    registry = PolicyBundleRegistry()

    decision, activated = PolicyActivationService(registry, store).activate_verified(
        PolicySignatureVerifier({"release-key": key}),
        PolicyApprovalVerifier({"approver-1": APPROVER_KEY}),
    )

    assert decision.decision is DecisionAction.ALLOW
    assert activated == bundle


def test_activation_denies_tampered_store(tmp_path) -> None:
    key = b"z" * 32
    bundle = parse_policy_bundle("active-policy", 1, SOURCE)
    signed = sign_policy_bundle(bundle, signer_id="release-key", key=key)
    path = tmp_path / "policy.jsonl"
    store = DurablePolicyBundleStore(path)
    store.append(signed, create_approval(
        "approval-1", "approver-1", signed, key=APPROVER_KEY
    ))
    path.write_text(path.read_text(encoding="utf-8").replace(bundle.content_fingerprint, "0" * 64), encoding="utf-8")

    decision, activated = PolicyActivationService(PolicyBundleRegistry(), store).activate_verified(
        PolicySignatureVerifier({"release-key": key}),
        PolicyApprovalVerifier({"approver-1": APPROVER_KEY}),
    )

    assert decision.decision is DecisionAction.DENY
    assert decision.reason_codes in {
        (ReasonCode.POLICY_SIGNATURE_INVALID,),
        (ReasonCode.POLICY_STORE_INVALID,),
    }
    assert activated is None
