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
from agent_security.identity import is_valid_identity
from agent_security.mcp.contracts import (
    MCPDescriptionScannerContract,
    MCPManifestRegistryContract,
    MCPPermissionContract,
    MCPResultCapabilityContract,
)
from agent_security.mcp.description_scanner import MCPDescriptionScanner
from agent_security.mcp.manifest import MCPManifestRegistry, MCPToolManifest
from agent_security.mcp.models import MCPAuthorizationResult, MCPAuthorizeRequest
from agent_security.mcp.permissions import MCPPermissionModel
from agent_security.mcp.result_capabilities import MCPResultCapabilityStore
from agent_security.tools.firewall import ToolFirewall
from agent_security.tools.contracts import ToolAuthorizerContract
from agent_security.tools.schemas import ToolAuthorizationResult, ToolAuthorizeRequest
from detection.models import DetectionFinding, RuleAction, Severity
from policy.engine import PolicyEngine
from policy.runtime import decide_with_active_policy
from telemetry.audit import StructuredAuditLogger


class MCPGateway:
    def __init__(
        self,
        manifests: MCPManifestRegistryContract | None = None,
        permissions: MCPPermissionContract | None = None,
        tool_firewall: ToolAuthorizerContract | None = None,
        *,
        description_scanner: MCPDescriptionScannerContract | None = None,
        result_capabilities: MCPResultCapabilityContract | None = None,
        policy_detector: DetectionEngineContract | None = None,
        risk_engine: RiskEngine | None = None,
        policy_engine: PolicyEngine | None = None,
        audit_logger: StructuredAuditLogger | None = None,
        event_factory: SecurityEventFactory | None = None,
    ) -> None:
        self._manifests = manifests or MCPManifestRegistry()
        self._permissions = permissions or MCPPermissionModel()
        self._tool_firewall = tool_firewall or ToolFirewall(policy_detector=policy_detector)
        self._description_scanner = description_scanner or MCPDescriptionScanner()
        self._result_capabilities = result_capabilities or MCPResultCapabilityStore()
        self._policy_detector = policy_detector
        self._risk_engine = risk_engine or RiskEngine()
        self._policy_engine = policy_engine or PolicyEngine()
        self._audit_logger = audit_logger or StructuredAuditLogger()
        self._event_factory = event_factory or SecurityEventFactory()

    def authorize(
        self,
        request: MCPAuthorizeRequest,
        *,
        verified_agent_id: str | None = None,
        verified_server_id: str | None = None,
    ) -> MCPAuthorizationResult:
        agent_identity_valid = is_valid_identity(verified_agent_id)
        server_identity_valid = is_valid_identity(verified_server_id)
        active_agent_id = verified_agent_id if agent_identity_valid else None
        event = self._event_factory.create(
            event_type="mcp.tool.authorize",
            source="mcp_gateway",
            action="authorize",
            target=request.server_id,
            resource_type="mcp_tool",
            trust_level=TrustLevel.UNTRUSTED,
            session_id=request.session_id,
            agent_id=active_agent_id,
            data={
                "server_fingerprint": fingerprint_text(request.server_id),
                "server_version_fingerprint": fingerprint_text(request.server_version),
                "tool": request.tool,
                "argument_names": sorted(request.arguments),
                "requested_scopes": sorted(request.requested_scopes),
            },
        )
        tool_result: ToolAuthorizationResult | None = None
        result_capability: str | None = None
        try:
            finding, tool_manifest = self._validate(
                request,
                active_agent_id,
                verified_server_id if server_identity_valid else None,
            )
            if finding is None and tool_manifest is not None:
                tool_result = self._tool_firewall.authorize(
                    ToolAuthorizeRequest(
                        tool=tool_manifest.local_tool_name,
                        arguments=request.arguments,
                        session_id=request.session_id,
                    ),
                    verified_agent_id=active_agent_id,
                )
                if tool_result.decision.decision is DecisionAction.ALLOW:
                    finding = self._finding("ASEC-MCP-GRANT-001", ReasonCode.MCP_AUTHORIZED, deny=False)
                else:
                    finding = self._finding(
                        "ASEC-MCP-TOOL-DENY-001",
                        ReasonCode.MCP_TOOL_AUTHORIZATION_DENIED,
                        deny=True,
                        extra_reasons=tuple(
                            code.value for code in tool_result.decision.reason_codes
                        ),
                    )
            decision = self._decide(event, finding)
            if decision.decision is DecisionAction.ALLOW and active_agent_id is not None:
                result_capability = self._result_capabilities.issue(
                    authorization_event_id=event.event_id,
                    agent_id=active_agent_id,
                    server_id=request.server_id,
                    tool=request.tool,
                    session_id=request.session_id,
                )
        except Exception:
            decision = SecurityDecision(
                decision=DecisionAction.DENY,
                risk_score=100,
                reason_codes=(ReasonCode.UNKNOWN_SECURITY_STATE,),
            )

        self._audit_logger.record(event, decision)
        return MCPAuthorizationResult(
            event_id=event.event_id,
            decision=decision,
            server_id=request.server_id,
            tool=request.tool,
            tool_authorization_event_id=tool_result.event_id if tool_result else None,
            result_capability=result_capability,
        )

    def _validate(
        self,
        request: MCPAuthorizeRequest,
        verified_agent_id: str | None,
        verified_server_id: str | None,
    ) -> tuple[DetectionFinding | None, MCPToolManifest | None]:
        if verified_agent_id is None:
            return self._finding(
                "ASEC-MCP-IDENTITY-001",
                ReasonCode.AGENT_IDENTITY_UNVERIFIED,
                deny=True,
            ), None
        if verified_server_id is None or verified_server_id != request.server_id:
            return self._finding(
                "ASEC-MCP-SERVER-IDENTITY-001",
                ReasonCode.MCP_SERVER_IDENTITY_UNVERIFIED,
                deny=True,
            ), None
        manifest = self._manifests.get(request.server_id)
        if manifest is None:
            return self._finding("ASEC-MCP-SERVER-001", ReasonCode.MCP_SERVER_UNKNOWN, deny=True), None
        if manifest.version != request.server_version:
            return self._finding("ASEC-MCP-VERSION-001", ReasonCode.MCP_VERSION_MISMATCH, deny=True), None
        tool = next((item for item in manifest.tools if item.name == request.tool), None)
        if tool is None:
            return self._finding("ASEC-MCP-TOOL-001", ReasonCode.MCP_TOOL_UNDECLARED, deny=True), None
        if self._description_scanner.is_suspicious(tool.description):
            return self._finding(
                "ASEC-MCP-DESCRIPTION-001",
                ReasonCode.MCP_DESCRIPTION_INJECTION,
                deny=True,
            ), None
        requested = frozenset(request.requested_scopes)
        declared = frozenset(tool.declared_scopes)
        if not requested.issubset(declared):
            return self._finding("ASEC-MCP-SCOPE-001", ReasonCode.MCP_SCOPE_ESCALATION, deny=True), None
        if not self._permissions.allows(verified_agent_id, request.server_id, requested):
            return self._finding(
                "ASEC-MCP-PERMISSION-001",
                ReasonCode.MCP_PERMISSION_DENIED,
                deny=True,
            ), None
        return None, tool

    def _decide(self, event: SecurityEvent, finding: DetectionFinding) -> SecurityDecision:
        context = SecurityContext(user_trust=TrustLevel.TRUSTED, agent_trust=TrustLevel.TRUSTED)
        return decide_with_active_policy(
            event=event,
            context=context,
            findings=(finding,),
            risk_engine=self._risk_engine,
            policy_engine=self._policy_engine,
            policy_detector=self._policy_detector,
        )

    @staticmethod
    def _finding(
        rule_id: str,
        reason: ReasonCode,
        *,
        deny: bool,
        extra_reasons: tuple[str, ...] = (),
    ) -> DetectionFinding:
        return DetectionFinding(
            rule_id=rule_id,
            severity=Severity.CRITICAL if deny else Severity.INFO,
            risk_score=100 if deny else 0,
            actions=(RuleAction.DENY if deny else RuleAction.ALLOW, RuleAction.AUDIT),
            reason_codes=(reason.value, *extra_reasons),
        )
