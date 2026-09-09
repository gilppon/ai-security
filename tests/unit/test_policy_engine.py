from core.decisions.actions import DecisionAction
from core.decisions.reasons import ReasonCode
from core.risk.models import RiskContribution, RiskScore
from detection.models import DetectionFinding, RuleAction, Severity
from policy.engine import PolicyEngine


def risk(score: int) -> RiskScore:
    contributions = () if score == 0 else (
        RiskContribution(source="test", score=score, reason_code="TEST_RISK"),
    )
    return RiskScore(total=score, contributions=contributions)


def finding(*actions: RuleAction, score: int = 0) -> DetectionFinding:
    return DetectionFinding(
        rule_id="ASEC-TEST-001",
        severity=Severity.HIGH,
        risk_score=score,
        actions=actions,
    )


def test_no_matching_rule_defaults_to_deny_even_at_zero_risk() -> None:
    decision = PolicyEngine().decide(risk(0), ())

    assert decision.decision is DecisionAction.DENY
    assert decision.reason_codes == (ReasonCode.DEFAULT_DENY,)


def test_explicit_allow_at_low_risk_allows() -> None:
    decision = PolicyEngine().decide(risk(0), (finding(RuleAction.ALLOW),))

    assert decision.decision is DecisionAction.ALLOW
    assert ReasonCode.EXPLICIT_ALLOW in decision.reason_codes


def test_deny_takes_precedence_over_allow() -> None:
    decision = PolicyEngine().decide(
        risk(10),
        (finding(RuleAction.ALLOW, RuleAction.DENY),),
    )

    assert decision.decision is DecisionAction.DENY


def test_high_risk_overrides_explicit_allow() -> None:
    decision = PolicyEngine().decide(risk(90), (finding(RuleAction.ALLOW),))

    assert decision.decision is DecisionAction.DENY
    assert ReasonCode.RISK_THRESHOLD_DENY in decision.reason_codes

