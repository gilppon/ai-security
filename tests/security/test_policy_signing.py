import json

from core.decisions.actions import DecisionAction
from core.decisions.reasons import ReasonCode
from policy.lifecycle import PolicyBundleRegistry, parse_policy_bundle
from policy.signing import PolicySignatureVerifier, sign_policy_bundle
from telemetry.audit import InMemoryAuditSink, StructuredAuditLogger


SOURCE = """
id: ASEC-POLICY-SIGNED
title: Signed health policy
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


def test_signed_policy_publishes_only_after_verification() -> None:
    key = b"k" * 32
    bundle = parse_policy_bundle("signed-policy", 1, SOURCE)
    signed = sign_policy_bundle(bundle, signer_id="release-key", key=key)
    sink = InMemoryAuditSink()
    registry = PolicyBundleRegistry(audit_logger=StructuredAuditLogger(sink))

    result = registry.publish_signed(signed, PolicySignatureVerifier({"release-key": key}))

    assert result.decision.decision is DecisionAction.ALLOW
    assert result.bundle == bundle


def test_invalid_signature_is_denied_and_not_logged_raw() -> None:
    key = b"k" * 32
    bundle = parse_policy_bundle("signed-policy", 1, SOURCE)
    signed = sign_policy_bundle(bundle, signer_id="release-key", key=key)
    tampered = signed.model_copy(update={"signature": "0" * 64})
    sink = InMemoryAuditSink()
    registry = PolicyBundleRegistry(audit_logger=StructuredAuditLogger(sink))

    result = registry.publish_signed(tampered, PolicySignatureVerifier({"release-key": key}))

    assert result.decision.reason_codes == (ReasonCode.POLICY_SIGNATURE_INVALID,)
    assert registry.current() is None
    audit = json.loads(sink.records[0])
    assert "0" * 64 not in sink.records[0]
    assert audit["decision"] == "DENY"

