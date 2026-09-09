from datetime import UTC, datetime

import pytest

from core.context.models import SecurityContext
from core.events.models import SecurityEvent
from core.events.types import TrustLevel
from detection.engine import DetectionEngine
from detection.matcher import RuleEvaluationError
from detection.models import RuleAction
from detection.parser import AISecRuleParser, RuleParseError


RULE = """
id: ASEC-FS-001
title: Agent Credential File Access
category: filesystem
severity: critical
when:
  event_type: agent.file.read
match:
  resource:
    - "**/.ssh/**"
    - "**/.env"
unless:
  approved: true
risk:
  score: 100
actions:
  - deny
  - audit
"""


def file_event(resource: str) -> SecurityEvent:
    return SecurityEvent(
        event_id="evt_file",
        timestamp=datetime.now(UTC),
        event_type="agent.file.read",
        source="agent",
        resource_type="file",
        resource=resource,
        trust_level=TrustLevel.UNTRUSTED,
    )


def test_parser_and_detector_match_sensitive_path() -> None:
    rule = AISecRuleParser().parse(RULE)

    findings = DetectionEngine((rule,)).detect(
        file_event("/home/user/.ssh/id_rsa"),
        SecurityContext(),
    )

    assert len(findings) == 1
    assert findings[0].rule_id == "ASEC-FS-001"
    assert RuleAction.DENY in findings[0].actions


def test_unless_approval_suppresses_rule() -> None:
    rule = AISecRuleParser().parse(RULE)
    context = SecurityContext(session_attributes={"approved": True})

    assert DetectionEngine((rule,)).detect(file_event("/x/.env"), context) == ()


def test_non_matching_path_has_no_findings() -> None:
    rule = AISecRuleParser().parse(RULE)

    assert DetectionEngine((rule,)).detect(file_event("/workspace/readme.md"), SecurityContext()) == ()


def test_parser_rejects_duplicate_yaml_keys() -> None:
    duplicate = RULE + "\nrisk:\n  score: 1\n"

    with pytest.raises(RuleParseError, match="invalid AISec YAML"):
        AISecRuleParser().parse(duplicate)


def test_parser_rejects_unknown_schema_fields() -> None:
    with pytest.raises(RuleParseError, match="schema validation failed"):
        AISecRuleParser().parse(RULE + "\nexecute: arbitrary_code\n")


def test_evaluator_rejects_unsupported_fields() -> None:
    unsafe = RULE.replace("event_type: agent.file.read", "raw_payload: anything")
    rule = AISecRuleParser().parse(unsafe)

    with pytest.raises(RuleEvaluationError, match="unsupported rule field"):
        DetectionEngine((rule,)).detect(file_event("/x/.env"), SecurityContext())


def test_parser_rejects_yaml_aliases() -> None:
    aliased = RULE.replace(
        "when:\n  event_type: agent.file.read",
        "when: &condition\n  event_type: agent.file.read",
    ).replace(
        "match:\n  resource:",
        "match: *condition\nunused:\n  resource:",
    )

    with pytest.raises(RuleParseError, match="aliases are not allowed"):
        AISecRuleParser().parse(aliased)


def test_parser_rejects_oversized_rule() -> None:
    oversized = RULE + ("# padding\n" * 10_000)

    with pytest.raises(RuleParseError, match="size limit"):
        AISecRuleParser().parse(oversized)


def test_parser_rejects_overlapping_when_and_match_fields() -> None:
    ambiguous = RULE.replace(
        "match:\n  resource:",
        "match:\n  event_type: agent.file.read\n  resource:",
    )

    with pytest.raises(RuleParseError, match="schema validation failed"):
        AISecRuleParser().parse(ambiguous)
