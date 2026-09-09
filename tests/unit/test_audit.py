import json
from datetime import UTC, datetime

from core.decisions.actions import DecisionAction
from core.decisions.models import SecurityDecision
from core.decisions.reasons import ReasonCode
from core.events.models import SecurityEvent
from telemetry.audit import InMemoryAuditSink, StructuredAuditLogger


def test_audit_is_structured_and_redacts_secret_values() -> None:
    sink = InMemoryAuditSink()
    audit = StructuredAuditLogger(sink)
    event = SecurityEvent(
        event_id="evt_audit",
        timestamp=datetime.now(UTC),
        event_type="agent.tool.call",
        source="agent",
        data={"api_token": "sensitive-value", "safe": "metadata"},
    )
    decision = SecurityDecision(
        decision=DecisionAction.DENY,
        risk_score=100,
        reason_codes=(ReasonCode.EXPLICIT_DENY,),
    )

    audit.record(event, decision)
    serialized = sink.records[0]
    parsed = json.loads(serialized)

    assert "sensitive-value" not in serialized
    assert parsed["metadata"]["event_data"]["api_token"]["redacted"] is True
    assert parsed["metadata"]["event_data"]["safe"] == "metadata"
    assert parsed["reason_codes"] == ["EXPLICIT_DENY"]

