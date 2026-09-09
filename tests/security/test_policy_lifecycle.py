import json

from core.decisions.actions import DecisionAction
from core.decisions.reasons import ReasonCode
from policy.lifecycle import PolicyBundleRegistry, parse_policy_bundle
from telemetry.audit import InMemoryAuditSink, StructuredAuditLogger


SOURCE = """
id: ASEC-POLICY-001
title: Allow health check
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


def test_policy_registry_is_monotonic_and_audited() -> None:
    sink = InMemoryAuditSink()
    registry = PolicyBundleRegistry(audit_logger=StructuredAuditLogger(sink))
    first = parse_policy_bundle("core-policy", 1, SOURCE)
    second = parse_policy_bundle("core-policy", 2, SOURCE.replace("Allow health", "Allow health v2"))

    assert registry.publish(first).decision.decision is DecisionAction.ALLOW
    rollback = registry.publish(first)
    assert rollback.decision.reason_codes == (ReasonCode.POLICY_VERSION_ROLLBACK,)
    assert registry.publish(second).bundle == second
    assert registry.current() == second
    assert len(sink.records) == 3
    assert "core-policy" not in sink.records[0]
    assert json.loads(sink.records[0])["metadata"]["event_data"]["policy_id_fingerprint"]


def test_policy_registry_rejects_policy_switch() -> None:
    registry = PolicyBundleRegistry()
    assert registry.publish(parse_policy_bundle("one-policy", 1, SOURCE)).bundle is not None
    result = registry.publish(parse_policy_bundle("other-policy", 2, SOURCE))
    assert result.decision.decision is DecisionAction.DENY
    assert result.decision.reason_codes == (ReasonCode.POLICY_BUNDLE_INVALID,)

