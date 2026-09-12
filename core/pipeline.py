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
    enable_dual_path: bool = True

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

            # Fast-Fail Path: Immediate short-circuit on decisive critical threats (<0.5ms)
            if self.enable_dual_path and any(
                f.severity.value in ("CRITICAL", "critical") and f.rule_action.value in ("DENY", "TERMINATE", "deny", "terminate")
                for f in findings
            ):
                decision = SecurityDecision(
                    decision=DecisionAction.DENY,
                    risk_score=100,
                    reason_codes=tuple(
                        ReasonCode(f.rule_id) if f.rule_id in ReasonCode.__members__.values()
                        else ReasonCode.PROMPT_INJECTION_DETECTED
                        for f in findings
                    ) or (ReasonCode.PROMPT_INJECTION_DETECTED,),
                    metadata={"evaluation_path": "fast-fail"},
                )
            else:
                # Normal / Slow Path: In-depth risk score and full policy engine evaluation
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
