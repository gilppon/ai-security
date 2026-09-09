from typing import Protocol

from core.context.models import SecurityContext
from core.decisions.models import SecurityDecision
from core.events.models import SecurityEvent
from core.risk.models import RiskScore
from detection.models import DetectionFinding


class EventNormalizerContract(Protocol):
    def normalize(self, event: SecurityEvent) -> SecurityEvent: ...


class ContextBuilderContract(Protocol):
    def build(self, event: SecurityEvent) -> SecurityContext: ...


class DetectionEngineContract(Protocol):
    def detect(self, event: SecurityEvent, context: SecurityContext) -> tuple[DetectionFinding, ...]: ...


class RiskEngineContract(Protocol):
    def score(
        self,
        event: SecurityEvent,
        context: SecurityContext,
        findings: tuple[DetectionFinding, ...],
    ) -> RiskScore: ...


class PolicyEngineContract(Protocol):
    def decide(
        self,
        risk: RiskScore,
        findings: tuple[DetectionFinding, ...],
    ) -> SecurityDecision: ...


class AuditLoggerContract(Protocol):
    def record(self, event: SecurityEvent, decision: SecurityDecision) -> object: ...


class FailureInjectorContract(Protocol):
    def check(self, stage: str) -> None: ...
