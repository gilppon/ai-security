from datetime import UTC, datetime, timedelta

from core.decisions.reasons import ReasonCode
from runtime.behavior.anomaly import RuntimeAnomalyDetector
from runtime.behavior.profiles import BehaviorProfile
from runtime.models import RuntimeActivity, RuntimeObservation, RuntimeOutcome


NOW = datetime(2026, 9, 9, tzinfo=UTC)


def observation(
    index: int,
    activity: RuntimeActivity,
    *,
    outcome: RuntimeOutcome = RuntimeOutcome.ALLOWED,
    target: str | None = None,
) -> RuntimeObservation:
    return RuntimeObservation(
        runtime_event_id=f"evt_{index}",
        source_event_id=None,
        timestamp=NOW + timedelta(seconds=index),
        session_id="session-1",
        agent_id="agent-1",
        activity=activity,
        outcome=outcome,
        target_fingerprint=target,
    )


def profile(**overrides) -> BehaviorProfile:
    values = {
        "agent_id": "agent-1",
        "allowed_activities": frozenset(RuntimeActivity),
        "window_seconds": 60,
        "max_events_per_window": 10,
        "max_denied_per_window": 3,
        "max_distinct_targets_per_window": 5,
    }
    values.update(overrides)
    return BehaviorProfile(**values)


def reasons(findings) -> set[str]:
    return {finding.reason_code for finding in findings}


def test_normal_behavior_has_no_anomaly() -> None:
    findings = RuntimeAnomalyDetector().detect(
        (observation(0, RuntimeActivity.PROMPT),),
        profile(),
    )

    assert findings == ()


def test_activity_rate_denial_and_target_rules_are_deterministic() -> None:
    observations = (
        observation(0, RuntimeActivity.PROMPT, outcome=RuntimeOutcome.BLOCKED, target="a" * 16),
        observation(1, RuntimeActivity.OUTPUT, outcome=RuntimeOutcome.FAILED, target="b" * 16),
    )
    findings = RuntimeAnomalyDetector().detect(
        observations,
        profile(
            allowed_activities=frozenset({RuntimeActivity.PROMPT}),
            max_events_per_window=1,
            max_denied_per_window=1,
            max_distinct_targets_per_window=1,
        ),
    )

    assert reasons(findings) == {
        ReasonCode.RUNTIME_ACTIVITY_DENIED.value,
        ReasonCode.RUNTIME_RATE_ANOMALY.value,
        ReasonCode.RUNTIME_DENIAL_BURST.value,
        ReasonCode.RUNTIME_TARGET_FANOUT.value,
    }


def test_blocked_prompt_followed_by_tool_call_is_correlated() -> None:
    findings = RuntimeAnomalyDetector().detect(
        (
            observation(0, RuntimeActivity.PROMPT, outcome=RuntimeOutcome.BLOCKED),
            observation(1, RuntimeActivity.TOOL_CALL),
        ),
        profile(),
    )

    assert ReasonCode.RUNTIME_BYPASS_SEQUENCE.value in reasons(findings)


def test_file_to_network_sequence_is_correlated() -> None:
    findings = RuntimeAnomalyDetector().detect(
        (
            observation(0, RuntimeActivity.FILE_ACCESS),
            observation(1, RuntimeActivity.NETWORK_REQUEST),
        ),
        profile(),
    )

    assert ReasonCode.RUNTIME_EXFILTRATION_SEQUENCE.value in reasons(findings)
