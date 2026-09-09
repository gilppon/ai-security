from core.decisions.actions import DecisionAction
from evaluation.catalog import default_resilience_catalog
from evaluation.scenarios import ResilienceResult, ResilienceRunner
from evaluation.faults import FaultStage
from core.decisions.models import SecurityDecision
from core.decisions.reasons import ReasonCode


def test_default_catalog_is_server_owned_and_bounded() -> None:
    scenarios = default_resilience_catalog()

    assert [scenario.scenario_id for scenario in scenarios] == [
        "pipeline-timeout",
        "audit-sink-failure",
        "resource-exhaustion",
    ]
    assert all(scenario.expected_decision is DecisionAction.DENY for scenario in scenarios)


def test_resilience_summary_reports_p95_and_failures() -> None:
    decision = SecurityDecision(
        decision=DecisionAction.DENY,
        risk_score=100,
        reason_codes=(ReasonCode.DEFAULT_DENY,),
    )
    results = tuple(
        ResilienceResult(
            scenario_id=f"scenario-{index}",
            stage=FaultStage.RISK,
            decision=decision,
            duration_ms=duration,
            within_budget=True,
            passed=index != 2,
        )
        for index, duration in enumerate((1, 2, 100, 4))
    )

    summary = ResilienceRunner.summarize(results)

    assert summary.total == 4
    assert summary.passed == 3
    assert summary.failed == 1
    assert summary.p95_duration_ms == 100
    assert summary.max_duration_ms == 100

