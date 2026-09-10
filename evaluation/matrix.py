"""Executable, deterministic Phase 11 fault matrix."""

from datetime import UTC, datetime

from core.context.builder import SecurityContextBuilder
from core.events.models import SecurityEvent
from core.events.types import TrustLevel
from core.normalization import EventNormalizer
from core.pipeline import SecurityPipeline
from core.risk.engine import RiskEngine
from detection.engine import DetectionEngine
from detection.parser import AISecRuleParser
from evaluation.catalog import default_resilience_catalog
from evaluation.faults import DeterministicFaultInjector, FaultStage
from evaluation.scenarios import ResilienceResult, ResilienceRunner
from policy.engine import PolicyEngine
from telemetry.audit import InMemoryAuditSink, StructuredAuditLogger


_ALLOW_STATUS_RULE = AISecRuleParser().parse(
    """
    id: ASEC-PHASE11-STATUS
    title: Phase 11 known status operation
    category: tool
    severity: info
    when:
      event_type: status.read
    match:
      action: read
    risk:
      score: 0
    actions: [allow, audit]
    """
)


def _run_stage(stage: FaultStage):
    injector = DeterministicFaultInjector(frozenset({stage}))
    pipeline = SecurityPipeline(
        normalizer=EventNormalizer(),
        context_builder=SecurityContextBuilder(),
        detector=DetectionEngine((_ALLOW_STATUS_RULE,)),
        risk_engine=RiskEngine(),
        policy_engine=PolicyEngine(),
        audit_logger=StructuredAuditLogger(InMemoryAuditSink()),
        failure_injector=injector,
    )
    event = SecurityEvent(
        event_id=f"phase11-{stage.value}",
        timestamp=datetime.now(UTC),
        event_type="status.read",
        source="PHASE11_CI",
        action="READ",
        trust_level=TrustLevel.TRUSTED,
    )
    return pipeline.evaluate(event)


def run_default_fault_matrix() -> tuple[ResilienceResult, ...]:
    scenarios = default_resilience_catalog()
    operations = tuple(
        (scenario, lambda stage=scenario.stage: _run_stage(stage))
        for scenario in scenarios
    )
    return ResilienceRunner().run_suite(operations)
