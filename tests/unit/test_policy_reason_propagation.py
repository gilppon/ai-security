from core.decisions.actions import DecisionAction
from core.decisions.reasons import ReasonCode
from core.risk.models import RiskContribution, RiskScore
from detection.models import DetectionFinding, RuleAction, Severity
from policy.engine import PolicyEngine


def test_known_finding_reason_reaches_final_decision() -> None:
    finding = DetectionFinding(
        rule_id="ASEC-FS-OUTSIDE",
        severity=Severity.CRITICAL,
        risk_score=100,
        actions=(RuleAction.DENY,),
        reason_codes=("PATH_OUTSIDE_ALLOWED_ROOT",),
    )
    risk = RiskScore(
        total=100,
        contributions=(RiskContribution(
            source="test",
            score=100,
            reason_code="TEST_RISK",
        ),),
    )

    decision = PolicyEngine().decide(risk, (finding,))

    assert decision.decision is DecisionAction.DENY
    assert ReasonCode.PATH_OUTSIDE_ALLOWED_ROOT in decision.reason_codes
