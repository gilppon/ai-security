from datetime import UTC, datetime

from core.context.builder import SecurityContextBuilder
from core.events.models import SecurityEvent
from core.events.types import TrustLevel
from core.normalization import EventNormalizer
from core.pipeline import SecurityPipeline
from core.risk.engine import RiskEngine
from detection.engine import DetectionEngine
from detection.parser import AISecRuleParser
from evaluation.faults import DeterministicFaultInjector, FaultStage
from policy.engine import PolicyEngine
from telemetry.audit import InMemoryAuditSink, StructuredAuditLogger
from core.decisions.actions import DecisionAction
from core.decisions.reasons import ReasonCode


def test_faulted_pipeline_fails_closed_and_audits() -> None:
    rule = AISecRuleParser().parse(
        """
        id: ASEC-STATUS-001
        title: Allow known status
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
    sink = InMemoryAuditSink()
    injector = DeterministicFaultInjector(frozenset({FaultStage.DETECT}))
    pipeline = SecurityPipeline(
        normalizer=EventNormalizer(),
        context_builder=SecurityContextBuilder(),
        detector=DetectionEngine((rule,)),
        risk_engine=RiskEngine(),
        policy_engine=PolicyEngine(),
        audit_logger=StructuredAuditLogger(sink),
        failure_injector=injector,
    )
    event = SecurityEvent(
        event_id="evt_fault",
        timestamp=datetime.now(UTC),
        event_type="status.read",
        source="TEST",
        action="READ",
        trust_level=TrustLevel.TRUSTED,
    )

    decision = pipeline.evaluate(event)

    assert decision.decision is DecisionAction.DENY
    assert decision.reason_codes == (ReasonCode.UNKNOWN_SECURITY_STATE,)
    assert injector.hits(FaultStage.DETECT) == 1
    assert len(sink.records) == 1
