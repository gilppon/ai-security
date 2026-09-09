from collections.abc import Iterable

from core.decisions.actions import ACTION_PRECEDENCE, DecisionAction
from core.decisions.models import SecurityDecision
from core.decisions.reasons import ReasonCode
from core.risk.models import RiskScore
from detection.models import DetectionFinding, RuleAction


RULE_TO_DECISION = {
    RuleAction.ALLOW: DecisionAction.ALLOW,
    RuleAction.LOG: DecisionAction.LOG,
    RuleAction.SANITIZE: DecisionAction.SANITIZE,
    RuleAction.APPROVAL_REQUIRED: DecisionAction.APPROVAL_REQUIRED,
    RuleAction.DENY: DecisionAction.DENY,
    RuleAction.QUARANTINE: DecisionAction.QUARANTINE,
    RuleAction.TERMINATE: DecisionAction.TERMINATE,
}


class PolicyEngine:
    def decide(
        self,
        risk: RiskScore,
        findings: Iterable[DetectionFinding],
    ) -> SecurityDecision:
        matched = tuple(findings)
        matched_rule_ids = tuple(item.rule_id for item in matched)
        requested_actions = {
            RULE_TO_DECISION[action]
            for finding in matched
            for action in finding.actions
            if action in RULE_TO_DECISION
        }

        threshold_action, threshold_reason = self._risk_action(risk.total)
        requested_actions.add(threshold_action)

        if not matched:
            return SecurityDecision(
                decision=DecisionAction.DENY,
                risk_score=risk.total,
                reason_codes=(ReasonCode.DEFAULT_DENY,),
            )

        selected = next(action for action in ACTION_PRECEDENCE if action in requested_actions)
        finding_reasons: list[ReasonCode] = []
        for finding in matched:
            for code in finding.reason_codes:
                try:
                    finding_reasons.append(ReasonCode(code))
                except ValueError:
                    continue
        reasons: list[ReasonCode] = [ReasonCode.RULE_MATCHED, *finding_reasons, threshold_reason]
        if selected is DecisionAction.ALLOW:
            reasons.append(ReasonCode.EXPLICIT_ALLOW)
        elif selected in {DecisionAction.DENY, DecisionAction.QUARANTINE, DecisionAction.TERMINATE}:
            reasons.append(ReasonCode.EXPLICIT_DENY)
        else:
            reasons.append(ReasonCode.POLICY_ACTION)

        return SecurityDecision(
            decision=selected,
            risk_score=risk.total,
            reason_codes=tuple(dict.fromkeys(reasons)),
            matched_rules=matched_rule_ids,
        )

    @staticmethod
    def _risk_action(score: int) -> tuple[DecisionAction, ReasonCode]:
        if score >= 80:
            return DecisionAction.DENY, ReasonCode.RISK_THRESHOLD_DENY
        if score >= 61:
            return DecisionAction.APPROVAL_REQUIRED, ReasonCode.RISK_THRESHOLD_APPROVAL
        if score >= 41:
            return DecisionAction.SANITIZE, ReasonCode.RISK_THRESHOLD_SANITIZE
        if score >= 21:
            return DecisionAction.LOG, ReasonCode.RISK_THRESHOLD_LOG
        return DecisionAction.ALLOW, ReasonCode.EXPLICIT_ALLOW
