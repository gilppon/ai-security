from agent_security.identity import is_valid_identity
from agent_security.mcp.contracts import MCPResultCapabilityContract
from agent_security.mcp.models import MCPResultInspectionResult, MCPResultRequest
from content_security.firewall import ContentFirewall
from content_security.models import ContentScanRequest, ContentSourceType, ContentType
from core.context.models import SecurityContext
from core.contracts import DetectionEngineContract
from core.decisions.actions import ACTION_PRECEDENCE, DecisionAction
from core.decisions.models import SecurityDecision
from core.decisions.reasons import ReasonCode
from core.events.factory import SecurityEventFactory
from core.events.models import SecurityEvent
from core.events.types import TrustLevel
from core.fingerprints import fingerprint_text
from core.risk.engine import RiskEngine
from detection.models import DetectionFinding, RuleAction, Severity
from output_security.guard import OutputGuard
from output_security.models import OutputScanRequest, OutputSource
from policy.engine import PolicyEngine
from policy.runtime import decide_with_active_policy
from telemetry.audit import StructuredAuditLogger


_RELEASABLE = frozenset({
    DecisionAction.ALLOW,
    DecisionAction.LOG,
    DecisionAction.SANITIZE,
})


class MCPResultGateway:
    def __init__(
        self,
        capabilities: MCPResultCapabilityContract,
        *,
        content_firewall: ContentFirewall | None = None,
        output_guard: OutputGuard | None = None,
        policy_detector: DetectionEngineContract | None = None,
        risk_engine: RiskEngine | None = None,
        policy_engine: PolicyEngine | None = None,
        audit_logger: StructuredAuditLogger | None = None,
        event_factory: SecurityEventFactory | None = None,
    ) -> None:
        self._capabilities = capabilities
        self._content_firewall = content_firewall or ContentFirewall(policy_detector=policy_detector)
        self._output_guard = output_guard or OutputGuard(policy_detector=policy_detector)
        self._policy_detector = policy_detector
        self._risk_engine = risk_engine or RiskEngine()
        self._policy_engine = policy_engine or PolicyEngine()
        self._audit_logger = audit_logger or StructuredAuditLogger()
        self._event_factory = event_factory or SecurityEventFactory()

    def inspect(
        self,
        request: MCPResultRequest,
        *,
        verified_agent_id: str | None = None,
        verified_server_id: str | None = None,
    ) -> MCPResultInspectionResult:
        result_fingerprint = fingerprint_text(request.content)
        identity_valid = (
            is_valid_identity(verified_agent_id)
            and is_valid_identity(verified_server_id)
        )
        event = self._event_factory.create(
            event_type="mcp.result.inspect",
            source="mcp_result_gateway",
            action="inspect",
            target="output_security",
            resource_type="mcp_result",
            trust_level=TrustLevel.UNTRUSTED,
            agent_id=verified_agent_id if identity_valid else None,
            data={
                "capability_fingerprint": fingerprint_text(request.result_capability),
                "result_fingerprint": result_fingerprint,
                "result_length": len(request.content),
                "server_fingerprint": fingerprint_text(verified_server_id or "unverified"),
            },
        )
        authorization_event_id = None
        content_result = None
        output_result = None
        released_result = None
        try:
            reason: ReasonCode | None
            if not identity_valid:
                reason = ReasonCode.MCP_RESULT_IDENTITY_MISMATCH
            else:
                grant, reason = self._capabilities.consume(
                    request.result_capability,
                    agent_id=verified_agent_id or "",
                    server_id=verified_server_id or "",
                )
                if grant is not None:
                    authorization_event_id = grant.authorization_event_id
                    event = event.model_copy(update={
                        "session_id": grant.session_id,
                        "agent_id": grant.agent_id,
                        "data": {
                            **event.data,
                            "authorization_event_fingerprint": fingerprint_text(
                                grant.authorization_event_id
                            ),
                            "tool_fingerprint": fingerprint_text(grant.tool),
                        },
                    })
                    content_result = self._content_firewall.scan(
                        ContentScanRequest(
                            content=request.content,
                            content_type=ContentType.PLAIN_TEXT,
                            source_type=ContentSourceType.TOOL_RESULT,
                            session_id=grant.session_id,
                        ),
                        verified_source_trust=TrustLevel.UNTRUSTED,
                    )
                    if (
                        content_result.decision.decision not in _RELEASABLE
                        or content_result.context is None
                    ):
                        reason = ReasonCode.MCP_RESULT_CONTENT_DENIED
                    else:
                        output_result = self._output_guard.scan(
                            OutputScanRequest(
                                output=content_result.context.content,
                                session_id=grant.session_id,
                            ),
                            source=OutputSource.MCP_RESULT,
                        )
                        if (
                            output_result.decision.decision not in _RELEASABLE
                            or output_result.released_output is None
                        ):
                            reason = ReasonCode.MCP_RESULT_OUTPUT_DENIED
                        else:
                            reason = ReasonCode.MCP_RESULT_AUTHORIZED
                            released_result = output_result.released_output
            decision = self._decide(
                event,
                reason or ReasonCode.UNKNOWN_SECURITY_STATE,
                content_result.decision if content_result else None,
                output_result.decision if output_result else None,
            )
        except Exception:
            decision = SecurityDecision(
                decision=DecisionAction.DENY,
                risk_score=100,
                reason_codes=(ReasonCode.UNKNOWN_SECURITY_STATE,),
            )
            released_result = None

        self._audit_logger.record(event, decision)
        return MCPResultInspectionResult(
            event_id=event.event_id,
            decision=decision,
            authorization_event_id=authorization_event_id,
            content_event_id=content_result.event_id if content_result else None,
            output_event_id=output_result.event_id if output_result else None,
            result_fingerprint=result_fingerprint,
            released_fingerprint=(
                fingerprint_text(released_result) if released_result is not None else None
            ),
            released_result=released_result,
        )

    def _decide(
        self,
        event: SecurityEvent,
        reason: ReasonCode,
        content_decision: SecurityDecision | None,
        output_decision: SecurityDecision | None,
    ) -> SecurityDecision:
        allowed = reason is ReasonCode.MCP_RESULT_AUTHORIZED
        child_decisions = tuple(
            item for item in (content_decision, output_decision) if item is not None
        )
        action = (
            next(
                candidate
                for candidate in ACTION_PRECEDENCE
                if any(item.decision is candidate for item in child_decisions)
            )
            if allowed and child_decisions
            else DecisionAction.DENY
        )
        risk_score = max(
            (item.risk_score for item in child_decisions),
            default=0 if allowed else 100,
        )
        finding = DetectionFinding(
            rule_id="ASEC-MCP-RESULT-001",
            severity=Severity.INFO if allowed else Severity.CRITICAL,
            risk_score=risk_score,
            actions=(RuleAction(action.value.lower()), RuleAction.AUDIT),
            reason_codes=(reason.value,),
        )
        context = SecurityContext(
            user_trust=TrustLevel.TRUSTED,
            agent_trust=TrustLevel.TRUSTED,
        )
        return decide_with_active_policy(
            event=event,
            context=context,
            findings=(finding,),
            risk_engine=self._risk_engine,
            policy_engine=self._policy_engine,
            policy_detector=self._policy_detector,
        )
