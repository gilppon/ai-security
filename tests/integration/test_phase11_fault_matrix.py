import json

from core.decisions.actions import DecisionAction
from core.decisions.models import SecurityDecision
from core.decisions.reasons import ReasonCode
from evaluation.__main__ import main
from evaluation.faults import FaultStage
from evaluation.matrix import run_default_fault_matrix
from evaluation.scenarios import ResilienceResult


def test_complete_fault_matrix_fails_closed_with_reason_codes() -> None:
    results = run_default_fault_matrix()

    assert [result.stage for result in results] == list(FaultStage)
    assert all(result.decision.decision is DecisionAction.DENY for result in results)
    assert all(
        result.decision.reason_codes == (ReasonCode.UNKNOWN_SECURITY_STATE,)
        for result in results
    )
    assert all(result.passed for result in results)


def test_phase11_cli_writes_sanitized_evidence_and_returns_success(tmp_path) -> None:
    target = tmp_path / "phase11.json"

    exit_code = main(["--evidence", str(target)])
    stored = json.loads(target.read_text(encoding="utf-8"))

    assert exit_code == 0
    assert stored["passed"] is True
    assert stored["summary"]["total"] == len(FaultStage)
    assert {item["stage"] for item in stored["results"]} == {
        stage.value for stage in FaultStage
    }


def test_phase11_cli_returns_failure_when_latency_gate_fails(tmp_path, monkeypatch) -> None:
    result = ResilienceResult(
        scenario_id="risk-stage-failure",
        stage=FaultStage.RISK,
        decision=SecurityDecision(
            decision=DecisionAction.DENY,
            risk_score=100,
            reason_codes=(ReasonCode.UNKNOWN_SECURITY_STATE,),
        ),
        duration_ms=20,
        within_budget=True,
        decision_matches=True,
        reason_codes_match=True,
        passed=True,
    )
    monkeypatch.setattr("evaluation.__main__.run_default_fault_matrix", lambda: (result,))

    exit_code = main(
        [
            "--evidence",
            str(tmp_path / "failed.json"),
            "--p95-limit-ms",
            "10",
            "--max-limit-ms",
            "10",
        ]
    )

    assert exit_code == 1
