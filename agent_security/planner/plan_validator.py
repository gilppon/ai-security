import json

from agent_security.chaining.confused_deputy import PlanChainPolicy
from agent_security.chaining.contracts import PlanChainPolicyContract
from agent_security.chaining.models import PlanChainStep
from agent_security.identity import is_valid_identity
from agent_security.planner.models import (
    AgentPlanRequest,
    PlanStep,
    PlanStepAssessment,
    PlanValidationResult,
)
from agent_security.tools.contracts import (
    ToolArgumentValidatorContract,
    ToolRegistryContract,
)
from agent_security.tools.registry import ToolRegistry
from agent_security.tools.schemas import ToolDefinition
from agent_security.tools.validator import ToolArgumentValidator
from core.context.models import SecurityContext
from core.contracts import DetectionEngineContract
from core.decisions.actions import DecisionAction
from core.decisions.models import SecurityDecision
from core.decisions.reasons import ReasonCode
from core.events.factory import SecurityEventFactory
from core.events.models import SecurityEvent
from core.events.types import TrustLevel
from core.fingerprints import fingerprint_text
from core.risk.engine import RiskEngine
from detection.models import DetectionFinding, RuleAction, Severity
from policy.engine import PolicyEngine
from policy.runtime import decide_with_active_policy
from telemetry.audit import StructuredAuditLogger


class PlanValidator:
    def __init__(
        self,
        registry: ToolRegistryContract | None = None,
        *,
        argument_validator: ToolArgumentValidatorContract | None = None,
        chain_policy: PlanChainPolicyContract | None = None,
        policy_detector: DetectionEngineContract | None = None,
        risk_engine: RiskEngine | None = None,
        policy_engine: PolicyEngine | None = None,
        audit_logger: StructuredAuditLogger | None = None,
        event_factory: SecurityEventFactory | None = None,
    ) -> None:
        self._registry = registry or ToolRegistry()
        self._argument_validator = argument_validator or ToolArgumentValidator()
        self._chain_policy = chain_policy or PlanChainPolicy()
        self._policy_detector = policy_detector
        self._risk_engine = risk_engine or RiskEngine()
        self._policy_engine = policy_engine or PolicyEngine()
        self._audit_logger = audit_logger or StructuredAuditLogger()
        self._event_factory = event_factory or SecurityEventFactory()

    def validate(
        self,
        request: AgentPlanRequest,
        *,
        verified_agent_id: str | None = None,
    ) -> PlanValidationResult:
        identity_valid = is_valid_identity(verified_agent_id)
        agent_id = verified_agent_id if identity_valid else None
        plan_fingerprint = _plan_fingerprint(request)
        event = self._event_factory.create(
            event_type="agent.plan.validate",
            source="planner",
            action="validate",
            target="plan_validator",
            resource_type="agent_plan",
            trust_level=TrustLevel.TRUSTED if identity_valid else TrustLevel.UNKNOWN,
            session_id=request.session_id,
            agent_id=agent_id,
            data={
                "plan_fingerprint": plan_fingerprint,
                "plan_id_fingerprint": fingerprint_text(request.plan_id),
                "step_count": len(request.steps),
                "tool_fingerprints": [
                    fingerprint_text(step.tool) for step in request.steps
                ],
            },
        )
        assessments: tuple[PlanStepAssessment, ...] = ()
        try:
            if agent_id is None:
                findings = (_deny_finding(
                    "ASEC-PLAN-IDENTITY-001",
                    ReasonCode.PLAN_IDENTITY_UNVERIFIED,
                ),)
            else:
                assessments, definitions, findings = self._precheck(request, agent_id)
                findings = (*findings, *self._chain_findings(request, definitions))
            decision = self._decide(event, findings)
        except Exception:
            assessments = ()
            decision = SecurityDecision(
                decision=DecisionAction.DENY,
                risk_score=100,
                reason_codes=(ReasonCode.UNKNOWN_SECURITY_STATE,),
            )

        self._audit_logger.record(event, decision)
        return PlanValidationResult(
            event_id=event.event_id,
            plan_id=request.plan_id,
            plan_fingerprint=plan_fingerprint,
            decision=decision,
            step_count=len(request.steps),
            step_assessments=assessments,
            execution_authorized=False,
        )

    def _precheck(
        self,
        request: AgentPlanRequest,
        agent_id: str,
    ) -> tuple[
        tuple[PlanStepAssessment, ...],
        tuple[ToolDefinition | None, ...],
        tuple[DetectionFinding, ...],
    ]:
        assessments: list[PlanStepAssessment] = []
        definitions: list[ToolDefinition | None] = []
        findings: list[DetectionFinding] = []
        for step in request.steps:
            assessment, definition, finding = self._precheck_step(step, agent_id)
            assessments.append(assessment)
            definitions.append(definition)
            if finding is not None:
                findings.append(finding)
        return tuple(assessments), tuple(definitions), tuple(findings)

    def _precheck_step(
        self,
        step: PlanStep,
        agent_id: str,
    ) -> tuple[PlanStepAssessment, ToolDefinition | None, DetectionFinding | None]:
        definition = self._registry.get(step.tool)
        if definition is None:
            reason = ReasonCode.PLAN_TOOL_UNKNOWN
        elif agent_id not in definition.allowed_agents:
            reason = ReasonCode.PLAN_TOOL_NOT_ALLOWED
        elif self._argument_validator.validate(definition, step.arguments):
            reason = ReasonCode.PLAN_ARGUMENT_INVALID
        else:
            return PlanStepAssessment(
                step_id=step.step_id,
                tool=step.tool,
                capability=definition.capability,
                precheck_passed=True,
                reason_codes=(ReasonCode.PLAN_STEP_PRECHECK_PASSED,),
            ), definition, None

        return PlanStepAssessment(
            step_id=step.step_id,
            tool=step.tool,
            capability=definition.capability if definition else None,
            precheck_passed=False,
            reason_codes=(reason,),
        ), None, _deny_finding("ASEC-PLAN-STEP-001", reason)

    def _chain_findings(
        self,
        request: AgentPlanRequest,
        definitions: tuple[ToolDefinition | None, ...],
    ) -> tuple[DetectionFinding, ...]:
        steps = tuple(
            PlanChainStep(
                step_id=step.step_id,
                tool=step.tool,
                capability=definition.capability,
            )
            for step, definition in zip(request.steps, definitions, strict=True)
            if definition is not None
        )
        return tuple(
            _deny_finding(violation.rule_id, violation.reason_code)
            for violation in self._chain_policy.evaluate(steps)
        )

    def _decide(
        self,
        event: SecurityEvent,
        findings: tuple[DetectionFinding, ...],
    ) -> SecurityDecision:
        active_findings = findings or (_allow_finding(),)
        context = SecurityContext(
            user_trust=TrustLevel.TRUSTED,
            agent_trust=event.trust_level,
        )
        return decide_with_active_policy(
            event=event,
            context=context,
            findings=active_findings,
            risk_engine=self._risk_engine,
            policy_engine=self._policy_engine,
            policy_detector=self._policy_detector,
        )


def _plan_fingerprint(request: AgentPlanRequest) -> str:
    canonical = json.dumps(
        request.model_dump(mode="json"),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )
    return fingerprint_text(canonical)


def _allow_finding() -> DetectionFinding:
    return DetectionFinding(
        rule_id="ASEC-PLAN-PREFLIGHT-001",
        severity=Severity.INFO,
        risk_score=0,
        actions=(RuleAction.ALLOW, RuleAction.AUDIT),
        reason_codes=(
            ReasonCode.PLAN_VALIDATED.value,
            ReasonCode.PLAN_REQUIRES_STEP_AUTHORIZATION.value,
        ),
    )


def _deny_finding(rule_id: str, reason: ReasonCode) -> DetectionFinding:
    return DetectionFinding(
        rule_id=rule_id,
        severity=Severity.CRITICAL,
        risk_score=100,
        actions=(RuleAction.DENY, RuleAction.AUDIT),
        reason_codes=(reason.value,),
    )
