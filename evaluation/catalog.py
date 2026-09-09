from evaluation.faults import FaultStage
from evaluation.scenarios import ResilienceScenario
from core.decisions.actions import DecisionAction


def default_resilience_catalog() -> tuple[ResilienceScenario, ...]:
    """Return the bounded, server-owned Phase 11 fault catalog."""
    return (
        ResilienceScenario(
            scenario_id="pipeline-timeout",
            stage=FaultStage.RISK,
            expected_decision=DecisionAction.DENY,
            max_duration_ms=5_000,
        ),
        ResilienceScenario(
            scenario_id="audit-sink-failure",
            stage=FaultStage.AUDIT,
            expected_decision=DecisionAction.DENY,
            max_duration_ms=5_000,
        ),
        ResilienceScenario(
            scenario_id="resource-exhaustion",
            stage=FaultStage.CONTEXT,
            expected_decision=DecisionAction.DENY,
            max_duration_ms=5_000,
        ),
    )

