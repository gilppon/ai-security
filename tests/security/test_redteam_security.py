from core.decisions.actions import DecisionAction
from core.decisions.models import SecurityDecision
from core.decisions.reasons import ReasonCode
from detection.redteam.models import (
    ProbeCategory,
    ProbeSuite,
    ProbeTarget,
    ProbeTemplate,
)
from detection.redteam.runner import ScenarioRunner
from telemetry.audit import InMemoryAuditSink, StructuredAuditLogger


RAW_PROBE = "api_key=DoNotWriteThisProbeValue123"


def probe(target: ProbeTarget = ProbeTarget.OUTPUT_GUARD) -> ProbeTemplate:
    return ProbeTemplate(
        probe_id="secret-probe",
        category=ProbeCategory.SECRET_LEAK,
        target=target,
        payload={"output": RAW_PROBE},
        expected_decision=DecisionAction.DENY,
    )


class FailingEvaluator:
    def evaluate(self, candidate: ProbeTemplate) -> SecurityDecision:
        raise RuntimeError(RAW_PROBE)


class InvalidEvaluator:
    def evaluate(self, candidate: ProbeTemplate) -> object:
        return {"decision": "DENY"}


def test_missing_evaluator_fails_closed_even_when_expected_is_deny() -> None:
    report = ScenarioRunner().run(ProbeSuite(
        suite_id="suite-missing",
        probes=(probe(),),
    ))

    assert report.passed == 0
    assert report.decision.decision is DecisionAction.DENY
    assert report.results[0].actual_decision is None
    assert report.results[0].harness_reason_code is ReasonCode.REDTEAM_EVALUATOR_MISSING


def test_evaluator_failure_is_denied_and_raw_probe_never_leaves_runner() -> None:
    sink = InMemoryAuditSink()
    report = ScenarioRunner(
        {ProbeTarget.OUTPUT_GUARD: FailingEvaluator()},
        audit_logger=StructuredAuditLogger(sink),
    ).run(ProbeSuite(suite_id="suite-failure", probes=(probe(),)))

    assert report.decision.decision is DecisionAction.DENY
    assert report.results[0].harness_reason_code is ReasonCode.REDTEAM_EVALUATION_FAILED
    assert len(sink.records) == 2
    assert RAW_PROBE not in report.model_dump_json()
    assert RAW_PROBE not in "".join(sink.records)


def test_untyped_evaluator_result_cannot_satisfy_expected_deny() -> None:
    report = ScenarioRunner({
        ProbeTarget.OUTPUT_GUARD: InvalidEvaluator(),  # type: ignore[dict-item]
    }).run(ProbeSuite(suite_id="suite-invalid", probes=(probe(),)))

    assert report.passed == 0
    assert report.decision.decision is DecisionAction.DENY
    assert report.results[0].harness_reason_code is ReasonCode.REDTEAM_EVALUATION_FAILED
