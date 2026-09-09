from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from core.decisions.actions import DecisionAction
from core.decisions.models import SecurityDecision
from core.events.models import SecurityEvent
from core.events.types import TrustLevel


def valid_event(**updates: object) -> SecurityEvent:
    payload = {
        "event_id": "evt_test_1",
        "timestamp": datetime.now(UTC),
        "event_type": "agent.tool.call",
        "source": "agent",
        "trust_level": TrustLevel.UNTRUSTED,
    }
    payload.update(updates)
    return SecurityEvent.model_validate(payload)


def test_security_event_accepts_timezone_aware_timestamp() -> None:
    event = valid_event()

    assert event.event_type == "agent.tool.call"
    assert event.risk_score == 0


def test_security_event_rejects_naive_timestamp() -> None:
    with pytest.raises(ValidationError, match="timezone-aware"):
        valid_event(timestamp=datetime.now())


@pytest.mark.parametrize("score", [-1, 101])
def test_security_event_rejects_out_of_range_risk(score: int) -> None:
    with pytest.raises(ValidationError):
        valid_event(risk_score=score)


def test_security_event_rejects_unknown_fields() -> None:
    with pytest.raises(ValidationError):
        valid_event(raw_secret="must not exist")


def test_security_event_rejects_non_json_payload_objects() -> None:
    with pytest.raises(ValidationError):
        valid_event(data={"unsafe": object()})


def test_security_decision_requires_reason_code() -> None:
    with pytest.raises(ValidationError, match="at least one reason"):
        SecurityDecision(
            decision=DecisionAction.DENY,
            risk_score=100,
            reason_codes=(),
        )


def test_default_decision_is_deny() -> None:
    decision = SecurityDecision.default_deny()

    assert decision.decision is DecisionAction.DENY
    assert decision.reason_codes
