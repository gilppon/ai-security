"""Allowlisted Phase 11 CI evidence without raw security inputs."""

from __future__ import annotations

import json
import os
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from core.decisions.actions import DecisionAction
from core.decisions.reasons import ReasonCode
from evaluation.faults import FaultStage
from evaluation.scenarios import ResilienceResult, ResilienceRunner, ResilienceSummary


class LatencyThresholds(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    p95_duration_ms: int = Field(default=250, ge=1, le=60_000)
    max_duration_ms: int = Field(default=500, ge=1, le=60_000)


class ResilienceEvidenceItem(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    scenario_id: str
    stage: FaultStage
    decision: DecisionAction
    reason_codes: tuple[ReasonCode, ...]
    duration_ms: int = Field(ge=0)
    within_budget: bool
    decision_matches: bool
    reason_codes_match: bool
    passed: bool


class ResilienceEvidence(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    schema_version: Literal["phase11.v1"] = "phase11.v1"
    generated_at: datetime
    summary: ResilienceSummary
    thresholds: LatencyThresholds
    latency_gate_passed: bool
    passed: bool
    results: tuple[ResilienceEvidenceItem, ...]


def build_evidence(
    results: tuple[ResilienceResult, ...],
    thresholds: LatencyThresholds | None = None,
) -> ResilienceEvidence:
    limits = thresholds or LatencyThresholds()
    summary = ResilienceRunner.summarize(results)
    latency_gate_passed = (
        summary.p95_duration_ms <= limits.p95_duration_ms
        and summary.max_duration_ms <= limits.max_duration_ms
    )
    items = tuple(
        ResilienceEvidenceItem(
            scenario_id=result.scenario_id,
            stage=result.stage,
            decision=result.decision.decision,
            reason_codes=result.decision.reason_codes,
            duration_ms=result.duration_ms,
            within_budget=result.within_budget,
            decision_matches=result.decision_matches,
            reason_codes_match=result.reason_codes_match,
            passed=result.passed,
        )
        for result in results
    )
    return ResilienceEvidence(
        generated_at=datetime.now(UTC),
        summary=summary,
        thresholds=limits,
        latency_gate_passed=latency_gate_passed,
        passed=summary.failed == 0 and latency_gate_passed,
        results=items,
    )


def write_evidence(evidence: ResilienceEvidence, path: str | Path) -> Path:
    target = Path(path).resolve()
    target.parent.mkdir(parents=True, exist_ok=True)
    temporary = target.with_name(f".{target.name}.{os.getpid()}.tmp")
    payload = evidence.model_dump_json(indent=2) + "\n"
    try:
        with temporary.open("x", encoding="utf-8", newline="\n") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        temporary.replace(target)
    finally:
        temporary.unlink(missing_ok=True)
    return target


def safe_console_summary(evidence: ResilienceEvidence) -> str:
    failed = [
        {
            "scenario_id": item.scenario_id,
            "stage": item.stage.value,
            "decision": item.decision.value,
            "reason_codes": [code.value for code in item.reason_codes],
        }
        for item in evidence.results
        if not item.passed
    ]
    return json.dumps(
        {
            "phase": 11,
            "passed": evidence.passed,
            "failed": evidence.summary.failed,
            "p95_duration_ms": evidence.summary.p95_duration_ms,
            "max_duration_ms": evidence.summary.max_duration_ms,
            "latency_gate_passed": evidence.latency_gate_passed,
            "failed_stages": failed,
        },
        separators=(",", ":"),
        sort_keys=True,
    )
