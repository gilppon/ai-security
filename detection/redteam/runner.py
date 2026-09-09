import json
from collections.abc import Mapping
from typing import Protocol, runtime_checkable

from core.context.models import SecurityContext
from core.decisions.actions import DecisionAction
from core.decisions.models import SecurityDecision
from core.decisions.reasons import ReasonCode
from core.events.factory import SecurityEventFactory
from core.events.models import SecurityEvent
from core.events.types import TrustLevel
from core.fingerprints import fingerprint_text
from core.risk.engine import RiskEngine
from detection.models import DetectionFinding, RuleAction, Severity
from detection.redteam.models import (
    CategoryScore,
    ProbeCategory,
    ProbeResult,
    ProbeSuite,
    ProbeTarget,
    ProbeTemplate,
    RegressionReport,
)
from policy.engine import PolicyEngine
from telemetry.audit import StructuredAuditLogger


_BLOCKING_ACTIONS = frozenset({
    DecisionAction.DENY,
    DecisionAction.QUARANTINE,
    DecisionAction.TERMINATE,
})


@runtime_checkable
class ProbeEvaluator(Protocol):
    def evaluate(self, probe: ProbeTemplate) -> SecurityDecision: ...


class ScenarioRunner:
    def __init__(
        self,
        evaluators: Mapping[ProbeTarget, ProbeEvaluator] | None = None,
        *,
        risk_engine: RiskEngine | None = None,
        policy_engine: PolicyEngine | None = None,
        audit_logger: StructuredAuditLogger | None = None,
        event_factory: SecurityEventFactory | None = None,
    ) -> None:
        self._evaluators = dict(evaluators or {})
        self._risk_engine = risk_engine or RiskEngine()
        self._policy_engine = policy_engine or PolicyEngine()
        self._audit_logger = audit_logger or StructuredAuditLogger()
        self._event_factory = event_factory or SecurityEventFactory()

    def run(self, suite: ProbeSuite) -> RegressionReport:
        results = tuple(self._run_probe(suite.suite_id, probe) for probe in suite.probes)
        passed = sum(result.passed for result in results)
        suite_fingerprint = _suite_fingerprint(suite)
        event = self._event_factory.create(
            event_type="redteam.regression.run",
            source="redteam_runner",
            action="evaluate",
            target="security_controls",
            resource_type="probe_suite",
            trust_level=TrustLevel.TRUSTED,
            data={
                "suite_fingerprint": suite_fingerprint,
                "probe_count": len(results),
                "passed_count": passed,
            },
        )
        suite_passed = passed == len(results)
        decision = self._status_decision(
            event,
            passed=suite_passed,
            success_reason=ReasonCode.REDTEAM_SUITE_PASSED,
            failure_reason=ReasonCode.REDTEAM_REGRESSION_DETECTED,
            rule_suffix="SUITE",
        )
        self._audit_logger.record(event, decision)
        return RegressionReport(
            event_id=event.event_id,
            suite_id=suite.suite_id,
            suite_fingerprint=suite_fingerprint,
            decision=decision,
            total=len(results),
            passed=passed,
            regression_score_bps=_rate_bps(passed, len(results)),
            category_scores=_category_scores(results),
            results=results,
        )

    def _run_probe(self, suite_id: str, probe: ProbeTemplate) -> ProbeResult:
        payload_fingerprint = _payload_fingerprint(probe)
        actual: SecurityDecision | None = None
        evaluator = self._evaluators.get(probe.target)
        if evaluator is None:
            reason = ReasonCode.REDTEAM_EVALUATOR_MISSING
        else:
            try:
                candidate = evaluator.evaluate(probe)
                if not isinstance(candidate, SecurityDecision):
                    raise TypeError("probe evaluator returned an invalid result")
                actual = candidate
                reason = (
                    ReasonCode.REDTEAM_PROBE_PASSED
                    if actual.decision is probe.expected_decision
                    else ReasonCode.REDTEAM_EXPECTATION_MISMATCH
                )
            except Exception:
                reason = ReasonCode.REDTEAM_EVALUATION_FAILED

        passed = reason is ReasonCode.REDTEAM_PROBE_PASSED
        event = self._event_factory.create(
            event_type="redteam.probe.evaluate",
            source="redteam_runner",
            action="evaluate",
            target=probe.target.value,
            resource_type="redteam_probe",
            trust_level=TrustLevel.TRUSTED,
            data={
                "suite_fingerprint": fingerprint_text(suite_id),
                "probe_fingerprint": fingerprint_text(probe.probe_id),
                "payload_fingerprint": payload_fingerprint,
                "category": probe.category.value,
                "expected_decision": probe.expected_decision.value,
                "actual_decision": actual.decision.value if actual else "unavailable",
                "passed": passed,
            },
        )
        harness_decision = self._status_decision(
            event,
            passed=passed,
            success_reason=ReasonCode.REDTEAM_PROBE_PASSED,
            failure_reason=reason,
            rule_suffix="PROBE",
        )
        self._audit_logger.record(event, harness_decision)
        return ProbeResult(
            event_id=event.event_id,
            probe_id=probe.probe_id,
            category=probe.category,
            target=probe.target,
            payload_fingerprint=payload_fingerprint,
            expected_decision=probe.expected_decision,
            actual_decision=actual.decision if actual else None,
            actual_reason_codes=actual.reason_codes if actual else (),
            passed=passed,
            harness_reason_code=reason,
        )

    def _status_decision(
        self,
        event: SecurityEvent,
        *,
        passed: bool,
        success_reason: ReasonCode,
        failure_reason: ReasonCode,
        rule_suffix: str,
    ) -> SecurityDecision:
        reason = success_reason if passed else failure_reason
        finding = DetectionFinding(
            rule_id=f"ASEC-REDTEAM-{rule_suffix}",
            severity=Severity.INFO if passed else Severity.CRITICAL,
            risk_score=0 if passed else 100,
            actions=(
                RuleAction.ALLOW if passed else RuleAction.DENY,
                RuleAction.AUDIT,
            ),
            reason_codes=(reason.value,),
        )
        risk = self._risk_engine.score(
            event,
            SecurityContext(
                user_trust=TrustLevel.TRUSTED,
                agent_trust=TrustLevel.TRUSTED,
            ),
            (finding,),
        )
        return self._policy_engine.decide(risk, (finding,))


def _payload_fingerprint(probe: ProbeTemplate) -> str:
    canonical = json.dumps(
        probe.payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )
    return fingerprint_text(canonical)


def _suite_fingerprint(suite: ProbeSuite) -> str:
    identity = "|".join(
        f"{probe.probe_id}:{_payload_fingerprint(probe)}:{probe.expected_decision.value}"
        for probe in suite.probes
    )
    return fingerprint_text(f"{suite.suite_id}|{identity}")


def _rate_bps(numerator: int, denominator: int) -> int:
    return numerator * 10_000 // denominator


def _category_scores(results: tuple[ProbeResult, ...]) -> tuple[CategoryScore, ...]:
    scores: list[CategoryScore] = []
    for category in ProbeCategory:
        category_results = tuple(
            result for result in results if result.category is category
        )
        if not category_results:
            continue
        total = len(category_results)
        passed = sum(result.passed for result in category_results)
        blocked = sum(
            result.actual_decision in _BLOCKING_ACTIONS
            for result in category_results
        )
        scores.append(CategoryScore(
            category=category,
            total=total,
            passed=passed,
            blocked=blocked,
            pass_rate_bps=_rate_bps(passed, total),
            block_rate_bps=_rate_bps(blocked, total),
        ))
    return tuple(scores)
