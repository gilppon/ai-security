from collections.abc import Iterable

from core.context.models import SecurityContext
from core.events.models import SecurityEvent
from detection.matcher import rule_matches
from detection.models import AISecRule, DetectionFinding


class DetectionEngine:
    def __init__(self, rules: Iterable[AISecRule] = ()) -> None:
        self._rules = tuple(sorted(rules, key=lambda item: item.id))

    def detect(self, event: SecurityEvent, context: SecurityContext) -> tuple[DetectionFinding, ...]:
        return tuple(
            DetectionFinding(
                rule_id=rule.id,
                severity=rule.severity,
                risk_score=rule.risk.score,
                actions=rule.actions,
            )
            for rule in self._rules
            if rule_matches(rule, event, context)
        )

