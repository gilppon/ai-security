from core.decisions.actions import DecisionAction
from core.decisions.models import SecurityDecision
from core.decisions.reasons import ReasonCode
from evaluation.faults import FaultStage
from evaluation.scenarios import ResilienceRunner, ResilienceScenario


def test_resilience_runner_records_fail_closed_exception() -> None:
    scenario = ResilienceScenario(
        scenario_id="detect-fault",
        stage=FaultStage.DETECT,
        expected_decision=DecisionAction.DENY,
        max_duration_ms=1_000,
    )

    result = ResilienceRunner().run(scenario, lambda: (_ for _ in ()).throw(RuntimeError("hidden")))

    assert result.passed is True
    assert result.decision.reason_codes == (ReasonCode.UNKNOWN_SECURITY_STATE,)
    assert "hidden" not in str(result.decision.metadata)


def test_resilience_runner_rejects_duplicate_suite_ids() -> None:
    scenario = ResilienceScenario(
        scenario_id="same-id",
        stage=FaultStage.RISK,
        expected_decision=DecisionAction.DENY,
    )
    try:
        ResilienceRunner().run_suite(((scenario, lambda: SecurityDecision(
            decision=DecisionAction.DENY,
            risk_score=100,
            reason_codes=(ReasonCode.DEFAULT_DENY,),
        )), (scenario, lambda: SecurityDecision(
            decision=DecisionAction.DENY,
            risk_score=100,
            reason_codes=(ReasonCode.DEFAULT_DENY,),
        ))))
    except ValueError as exc:
        assert "unique" in str(exc)
    else:  # pragma: no cover
        raise AssertionError("duplicate resilience ids were accepted")


def test_resilience_runner_fails_on_reason_code_mismatch() -> None:
    scenario = ResilienceScenario(
        scenario_id="reason-mismatch",
        stage=FaultStage.POLICY,
        expected_decision=DecisionAction.DENY,
        expected_reason_codes=(ReasonCode.UNKNOWN_SECURITY_STATE,),
    )

    result = ResilienceRunner().run(
        scenario,
        lambda: SecurityDecision(
            decision=DecisionAction.DENY,
            risk_score=100,
            reason_codes=(ReasonCode.DEFAULT_DENY,),
        ),
    )

    assert result.decision_matches is True
    assert result.reason_codes_match is False
    assert result.passed is False
