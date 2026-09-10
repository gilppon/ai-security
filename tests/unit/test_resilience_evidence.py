import json

from core.decisions.actions import DecisionAction
from core.decisions.models import SecurityDecision
from core.decisions.reasons import ReasonCode
from evaluation.evidence import LatencyThresholds, build_evidence, safe_console_summary, write_evidence
from evaluation.faults import FaultStage
from evaluation.scenarios import ResilienceResult


def _result(*, duration_ms: int = 1, metadata=None) -> ResilienceResult:
    return ResilienceResult(
        scenario_id="policy-stage-failure",
        stage=FaultStage.POLICY,
        decision=SecurityDecision(
            decision=DecisionAction.DENY,
            risk_score=100,
            reason_codes=(ReasonCode.UNKNOWN_SECURITY_STATE,),
            metadata=metadata or {},
        ),
        duration_ms=duration_ms,
        within_budget=True,
        decision_matches=True,
        reason_codes_match=True,
        passed=True,
    )


def test_evidence_allowlist_excludes_raw_decision_metadata() -> None:
    evidence = build_evidence(
        (_result(metadata={"prompt": "RAW-PROMPT-MARKER", "secret": "RAW-SECRET-MARKER"}),)
    )

    serialized = evidence.model_dump_json()

    assert "RAW-PROMPT-MARKER" not in serialized
    assert "RAW-SECRET-MARKER" not in serialized
    assert "metadata" not in serialized
    assert evidence.results[0].reason_codes == (ReasonCode.UNKNOWN_SECURITY_STATE,)


def test_latency_threshold_violation_fails_evidence_gate() -> None:
    evidence = build_evidence(
        (_result(duration_ms=21),),
        LatencyThresholds(p95_duration_ms=10, max_duration_ms=20),
    )

    assert evidence.latency_gate_passed is False
    assert evidence.passed is False


def test_evidence_writer_and_console_output_remain_sanitized(tmp_path) -> None:
    evidence = build_evidence((_result(metadata={"payload": "RAW-PAYLOAD-MARKER"}),))

    path = write_evidence(evidence, tmp_path / "phase11.json")
    stored = json.loads(path.read_text(encoding="utf-8"))
    console = safe_console_summary(evidence)

    assert stored["schema_version"] == "phase11.v1"
    assert stored["passed"] is True
    assert "RAW-PAYLOAD-MARKER" not in path.read_text(encoding="utf-8")
    assert "RAW-PAYLOAD-MARKER" not in console
