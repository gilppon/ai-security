from evaluation.faults import FaultStage
from evaluation.scenarios import ResilienceScenario
from core.decisions.actions import DecisionAction
from core.decisions.reasons import ReasonCode


def default_resilience_catalog() -> tuple[ResilienceScenario, ...]:
    """Return the bounded, server-owned Phase 11 fault catalog."""
    return tuple(
        ResilienceScenario(
            scenario_id=f"{stage.value}-stage-failure",
            stage=stage,
            expected_decision=DecisionAction.DENY,
            expected_reason_codes=(ReasonCode.UNKNOWN_SECURITY_STATE,),
            max_duration_ms=1_000,
        )
        for stage in FaultStage
    )
