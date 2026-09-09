from collections.abc import Iterable

from core.context.models import SecurityContext
from core.context.trust import TRUST_RISK
from core.events.models import SecurityEvent
from core.risk.models import RiskContribution, RiskScore
from core.risk.scoring import calculate_risk
from core.risk.weights import MAX_PREVIOUS_VIOLATION_RISK, PER_PREVIOUS_VIOLATION_RISK
from detection.models import DetectionFinding


class RiskEngine:
    def score(
        self,
        event: SecurityEvent,
        context: SecurityContext,
        findings: Iterable[DetectionFinding] = (),
    ) -> RiskScore:
        contributions: list[RiskContribution] = []

        if event.risk_score:
            contributions.append(RiskContribution(
                source="event",
                score=event.risk_score,
                reason_code="EVENT_RISK",
            ))

        contributions.extend((
            RiskContribution(
                source="user_trust",
                score=TRUST_RISK[context.user_trust],
                reason_code="USER_TRUST_RISK",
            ),
            RiskContribution(
                source="agent_trust",
                score=TRUST_RISK[context.agent_trust],
                reason_code="AGENT_TRUST_RISK",
            ),
        ))

        if context.resource_sensitivity:
            contributions.append(RiskContribution(
                source="resource_sensitivity",
                score=context.resource_sensitivity,
                reason_code="RESOURCE_SENSITIVITY",
            ))

        violation_score = min(
            MAX_PREVIOUS_VIOLATION_RISK,
            context.previous_violations * PER_PREVIOUS_VIOLATION_RISK,
        )
        if violation_score:
            contributions.append(RiskContribution(
                source="previous_violations",
                score=violation_score,
                reason_code="PREVIOUS_VIOLATIONS",
            ))

        for finding in findings:
            contributions.append(RiskContribution(
                source=finding.rule_id,
                score=finding.risk_score,
                reason_code="RULE_RISK",
            ))

        return calculate_risk(contributions)

