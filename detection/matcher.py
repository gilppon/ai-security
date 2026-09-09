from fnmatch import fnmatchcase
from typing import Any

from core.context.models import SecurityContext
from core.events.models import SecurityEvent
from detection.models import AISecRule


ALLOWED_FIELDS = {
    "event_id", "event_type", "session_id", "user_id", "agent_id", "source",
    "target", "action", "resource_type", "resource", "trust_level", "risk_score",
    "user_trust", "agent_trust", "resource_sensitivity", "previous_violations",
    "approved",
}


class RuleEvaluationError(ValueError):
    pass


def _event_value(event: SecurityEvent, context: SecurityContext, field: str) -> Any:
    if field not in ALLOWED_FIELDS:
        raise RuleEvaluationError(f"unsupported rule field: {field}")
    if field == "approved":
        return bool(context.session_attributes.get("approved", False))
    if hasattr(event, field):
        return getattr(event, field)
    return getattr(context, field)


def _matches(actual: Any, expected: Any) -> bool:
    candidates = expected if isinstance(expected, list) else [expected]
    actual_text = str(actual.value if hasattr(actual, "value") else actual)
    for candidate in candidates:
        if not isinstance(candidate, (str, int, float, bool)):
            raise RuleEvaluationError("rule values must be scalar or scalar lists")
        candidate_text = str(candidate)
        if any(char in candidate_text for char in "*?["):
            normalized_actual = actual_text.replace("\\", "/")
            normalized_candidate = candidate_text.replace("\\", "/")
            if fnmatchcase(normalized_actual, normalized_candidate):
                return True
        elif actual == candidate or actual_text == candidate_text:
            return True
    return False


def rule_matches(rule: AISecRule, event: SecurityEvent, context: SecurityContext) -> bool:
    for field, expected in {**rule.when, **rule.match}.items():
        if not _matches(_event_value(event, context, field), expected):
            return False
    for field, expected in rule.unless.items():
        if _matches(_event_value(event, context, field), expected):
            return False
    return True

