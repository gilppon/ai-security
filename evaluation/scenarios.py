from __future__ import annotations

from collections.abc import Callable, Iterable
import math
import time

from pydantic import BaseModel, ConfigDict, Field

from core.decisions.actions import DecisionAction
from core.decisions.models import SecurityDecision
from core.decisions.reasons import ReasonCode
from evaluation.faults import FaultStage


class ResilienceScenario(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    scenario_id: str = Field(min_length=3, max_length=128, pattern=r"^[a-z0-9]+(?:[._-][a-z0-9]+)*$")
    stage: FaultStage
    expected_decision: DecisionAction
    max_duration_ms: int = Field(default=1_000, ge=1, le=60_000)


class ResilienceResult(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    scenario_id: str
    stage: FaultStage
    decision: SecurityDecision
    duration_ms: int = Field(ge=0)
    within_budget: bool
    passed: bool


class ResilienceSummary(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    total: int = Field(ge=1, le=100)
    passed: int = Field(ge=0, le=100)
    failed: int = Field(ge=0, le=100)
    max_duration_ms: int = Field(ge=0)
    p95_duration_ms: int = Field(ge=0)


class ResilienceRunner:
    def run(
        self,
        scenario: ResilienceScenario,
        operation: Callable[[], SecurityDecision],
    ) -> ResilienceResult:
        started = time.perf_counter()
        try:
            decision = operation()
        except Exception as exc:
            decision = SecurityDecision(
                decision=DecisionAction.DENY,
                risk_score=100,
                reason_codes=(ReasonCode.UNKNOWN_SECURITY_STATE,),
                metadata={"error_type": type(exc).__name__},
            )
        duration_ms = max(0, math.ceil((time.perf_counter() - started) * 1_000))
        within_budget = duration_ms <= scenario.max_duration_ms
        passed = decision.decision is scenario.expected_decision and within_budget
        return ResilienceResult(
            scenario_id=scenario.scenario_id,
            stage=scenario.stage,
            decision=decision,
            duration_ms=duration_ms,
            within_budget=within_budget,
            passed=passed,
        )

    def run_suite(
        self,
        scenarios: Iterable[tuple[ResilienceScenario, Callable[[], SecurityDecision]]],
    ) -> tuple[ResilienceResult, ...]:
        bounded = tuple(scenarios)
        if not 1 <= len(bounded) <= 100:
            raise ValueError("resilience suite must contain between 1 and 100 scenarios")
        ids = [scenario.scenario_id for scenario, _ in bounded]
        if len(ids) != len(set(ids)):
            raise ValueError("resilience scenario ids must be unique")
        return tuple(self.run(scenario, operation) for scenario, operation in bounded)

    @staticmethod
    def summarize(results: tuple[ResilienceResult, ...]) -> ResilienceSummary:
        if not 1 <= len(results) <= 100:
            raise ValueError("resilience results must contain between 1 and 100 items")
        durations = sorted(result.duration_ms for result in results)
        p95_index = min(len(durations) - 1, math.ceil(len(durations) * 0.95) - 1)
        passed = sum(result.passed for result in results)
        return ResilienceSummary(
            total=len(results),
            passed=passed,
            failed=len(results) - passed,
            max_duration_ms=max(durations),
            p95_duration_ms=durations[p95_index],
        )
