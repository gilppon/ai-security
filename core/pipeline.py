from dataclasses import dataclass

from core.contracts import (
    AuditLoggerContract,
    ContextBuilderContract,
    DetectionEngineContract,
    EventNormalizerContract,
    PolicyEngineContract,
    RiskEngineContract,
    FailureInjectorContract,
)
from core.decisions.actions import DecisionAction
from core.decisions.models import SecurityDecision
from core.decisions.reasons import ReasonCode
from core.events.models import SecurityEvent


@dataclass(frozen=True, slots=True)
class SecurityPipeline:
    normalizer: EventNormalizerContract
    context_builder: ContextBuilderContract
    detector: DetectionEngineContract
    risk_engine: RiskEngineContract
    policy_engine: PolicyEngineContract
    audit_logger: AuditLoggerContract
    failure_injector: FailureInjectorContract | None = None

    def evaluate(self, event: SecurityEvent) -> SecurityDecision:
        normalized = event
        try:
            if self.failure_injector is not None:
                self.failure_injector.check("normalize")
            normalized = self.normalizer.normalize(event)
            if self.failure_injector is not None:
                self.failure_injector.check("context")
            context = self.context_builder.build(normalized)
            if self.failure_injector is not None:
                self.failure_injector.check("detect")
            findings = self.detector.detect(normalized, context)
            if self.failure_injector is not None:
                self.failure_injector.check("risk")
            risk = self.risk_engine.score(normalized, context, findings)
            if self.failure_injector is not None:
                self.failure_injector.check("policy")
            decision = self.policy_engine.decide(risk, findings)
        except Exception as exc:
            decision = SecurityDecision(
                decision=DecisionAction.DENY,
                risk_score=100,
                reason_codes=(ReasonCode.UNKNOWN_SECURITY_STATE,),
                metadata={"error_type": type(exc).__name__},
            )
        if self.failure_injector is not None:
            self.failure_injector.check("audit")
        self.audit_logger.record(normalized, decision)
        return decision
