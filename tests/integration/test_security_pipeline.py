import json
from datetime import UTC, datetime

from core.context.builder import SecurityContextBuilder
from core.context.models import SecurityContext
from core.decisions.actions import DecisionAction
from core.events.models import SecurityEvent
from core.events.types import TrustLevel
from core.normalization import EventNormalizer
from core.pipeline import SecurityPipeline
from core.risk.engine import RiskEngine
from detection.engine import DetectionEngine
from detection.models import DetectionFinding
from detection.parser import AISecRuleParser
from policy.engine import PolicyEngine
from telemetry.audit import InMemoryAuditSink, StructuredAuditLogger


class FailingDetector:
    def detect(
        self,
        event: SecurityEvent,
        context: SecurityContext,
    ) -> tuple[DetectionFinding, ...]:
        raise RuntimeError("detector unavailable")


def test_event_flows_through_decision_and_audit() -> None:
    rule = AISecRuleParser().parse("""
id: ASEC-TOOL-001
title: Allow known low-risk status tool
category: tool
severity: info
when:
  event_type: agent.tool.call
match:
  action: status
risk:
  score: 0
actions: [allow, audit]
""")
    sink = InMemoryAuditSink()
    pipeline = SecurityPipeline(
        normalizer=EventNormalizer(),
        context_builder=SecurityContextBuilder(),
        detector=DetectionEngine((rule,)),
        risk_engine=RiskEngine(),
        policy_engine=PolicyEngine(),
        audit_logger=StructuredAuditLogger(sink),
    )
    event = SecurityEvent(
        event_id="evt_pipeline",
        timestamp=datetime.now(UTC),
        event_type="agent.tool.call",
        source="AGENT",
        action="STATUS",
        trust_level=TrustLevel.TRUSTED,
    )

    decision = pipeline.evaluate(event)

    assert decision.decision is DecisionAction.ALLOW
    assert decision.matched_rules == ("ASEC-TOOL-001",)
    assert json.loads(sink.records[0])["decision"] == "ALLOW"


def test_unknown_action_is_denied_and_audited() -> None:
    sink = InMemoryAuditSink()
    pipeline = SecurityPipeline(
        normalizer=EventNormalizer(),
        context_builder=SecurityContextBuilder(),
        detector=DetectionEngine(),
        risk_engine=RiskEngine(),
        policy_engine=PolicyEngine(),
        audit_logger=StructuredAuditLogger(sink),
    )
    event = SecurityEvent(
        event_id="evt_unknown",
        timestamp=datetime.now(UTC),
        event_type="agent.tool.call",
        source="agent",
        action="unknown",
    )

    decision = pipeline.evaluate(event)

    assert decision.decision is DecisionAction.DENY
    assert json.loads(sink.records[0])["reason_codes"] == ["DEFAULT_DENY"]


def test_internal_security_error_fails_closed_and_is_audited() -> None:
    sink = InMemoryAuditSink()
    pipeline = SecurityPipeline(
        normalizer=EventNormalizer(),
        context_builder=SecurityContextBuilder(),
        detector=FailingDetector(),
        risk_engine=RiskEngine(),
        policy_engine=PolicyEngine(),
        audit_logger=StructuredAuditLogger(sink),
    )
    event = SecurityEvent(
        event_id="evt_failure",
        timestamp=datetime.now(UTC),
        event_type="agent.tool.call",
        source="agent",
    )

    decision = pipeline.evaluate(event)
    audit_record = json.loads(sink.records[0])

    assert decision.decision is DecisionAction.DENY
    assert decision.risk_score == 100
    assert audit_record["reason_codes"] == ["UNKNOWN_SECURITY_STATE"]
    assert "detector unavailable" not in sink.records[0]
