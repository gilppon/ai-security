from datetime import UTC, datetime

from core.context.models import SecurityContext
from core.events.models import SecurityEvent
from core.events.types import TrustLevel
from core.risk.engine import RiskEngine
from detection.models import DetectionFinding, RuleAction, Severity


def event(*, risk_score: int = 0) -> SecurityEvent:
    return SecurityEvent(
        event_id="evt_risk",
        timestamp=datetime.now(UTC),
        event_type="agent.file.read",
        source="agent",
        trust_level=TrustLevel.UNTRUSTED,
        risk_score=risk_score,
    )


def test_trusted_empty_context_has_zero_risk() -> None:
    result = RiskEngine().score(
        event(),
        SecurityContext(user_trust=TrustLevel.TRUSTED, agent_trust=TrustLevel.TRUSTED),
    )

    assert result.total == 0


def test_unknown_trust_is_risky() -> None:
    result = RiskEngine().score(event(), SecurityContext())

    assert result.total == 50
    assert {item.reason_code for item in result.contributions} == {
        "USER_TRUST_RISK",
        "AGENT_TRUST_RISK",
    }


def test_risk_is_deterministic_and_capped_at_100() -> None:
    finding = DetectionFinding(
        rule_id="ASEC-FS-001",
        severity=Severity.CRITICAL,
        risk_score=90,
        actions=(RuleAction.DENY,),
    )
    context = SecurityContext(
        user_trust=TrustLevel.UNTRUSTED,
        agent_trust=TrustLevel.UNTRUSTED,
        resource_sensitivity=40,
        previous_violations=99,
    )

    first = RiskEngine().score(event(risk_score=100), context, (finding,))
    second = RiskEngine().score(event(risk_score=100), context, (finding,))

    assert first == second
    assert first.total == 100

