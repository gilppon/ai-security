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
from agent_security.tools.contracts import ToolArgumentValidatorContract, ToolRegistryContract
from agent_security.tools.registry import ToolRegistry
from agent_security.tools.schemas import (
    ToolAuthorizationResult,
    ToolAuthorizeRequest,
    ToolCapability,
    ToolDefinition,
)
from agent_security.tools.validator import ToolArgumentValidator
from detection.models import DetectionFinding, RuleAction, Severity
from policy.engine import PolicyEngine
from policy.runtime import decide_with_active_policy
from resource_security.api.models import APIAuthorizationRequest
from resource_security.contracts import (
    APIAuthorizer,
    DatabaseAuthorizer,
    FilesystemAuthorizer,
    NetworkAuthorizer,
    ProcessAuthorizer,
)
from resource_security.database.models import DatabaseAuthorizationRequest
from resource_security.filesystem.models import FilesystemAuthorizationRequest
from resource_security.models import ResourceAuthorizationResult
from resource_security.network.models import NetworkAuthorizationRequest
from resource_security.process.models import ProcessAuthorizationRequest, ProcessAuthorizationResult
from telemetry.audit import StructuredAuditLogger


class ToolFirewall:
    def __init__(
        self,
        registry: ToolRegistryContract | None = None,
        *,
        argument_validator: ToolArgumentValidatorContract | None = None,
        filesystem_firewall: FilesystemAuthorizer | None = None,
        network_firewall: NetworkAuthorizer | None = None,
        process_firewall: ProcessAuthorizer | None = None,
        database_firewall: DatabaseAuthorizer | None = None,
        api_firewall: APIAuthorizer | None = None,
        policy_detector: DetectionEngineContract | None = None,
        risk_engine: RiskEngine | None = None,
        policy_engine: PolicyEngine | None = None,
        audit_logger: StructuredAuditLogger | None = None,
        event_factory: SecurityEventFactory | None = None,
    ) -> None:
        self._registry = registry or ToolRegistry()
        self._validator = argument_validator or ToolArgumentValidator()
        self._filesystem_firewall = filesystem_firewall
        self._network_firewall = network_firewall
        self._process_firewall = process_firewall
        self._database_firewall = database_firewall
        self._api_firewall = api_firewall
        self._policy_detector = policy_detector
        self._risk_engine = risk_engine or RiskEngine()
        self._policy_engine = policy_engine or PolicyEngine()
        self._audit_logger = audit_logger or StructuredAuditLogger()
        self._event_factory = event_factory or SecurityEventFactory()

    def authorize(
        self,
        request: ToolAuthorizeRequest,
        *,
        verified_agent_id: str | None = None,
    ) -> ToolAuthorizationResult:
        identity_is_valid = is_valid_identity(verified_agent_id)
        active_agent_id = verified_agent_id if identity_is_valid else None
        event = self._event_factory.create(
            event_type="agent.tool.authorize",
            source="agent",
            action="authorize",
            target="tool_firewall",
            resource_type="tool",
            trust_level=TrustLevel.TRUSTED if identity_is_valid else TrustLevel.UNKNOWN,
            session_id=request.session_id,
            agent_id=active_agent_id,
            data={
                "tool": request.tool,
                "argument_names": sorted(request.arguments),
                "agent_fingerprint": fingerprint_text(active_agent_id or "unverified"),
            },
        )
        resource_result: ResourceAuthorizationResult | ProcessAuthorizationResult | None = None
        try:
            finding, definition = self._validate_request(request, active_agent_id)
            if finding is None and definition is not None:
                resource_result = self._authorize_resource(definition, request, active_agent_id)
                if resource_result is not None and resource_result.decision.decision is not DecisionAction.ALLOW:
                    resource_reasons = tuple(code.value for code in resource_result.decision.reason_codes)
                    finding = self._deny(
                        "ASEC-TOOL-RESOURCE-001",
                        ReasonCode.RESOURCE_AUTHORIZATION_DENIED,
                        extra_reasons=resource_reasons,
                    )
                else:
                    finding = self._allow()
            decision = self._decide(event, finding)
        except Exception:
            decision = SecurityDecision(
                decision=DecisionAction.DENY,
                risk_score=100,
                reason_codes=(ReasonCode.UNKNOWN_SECURITY_STATE,),
            )

        self._audit_logger.record(event, decision)
        return ToolAuthorizationResult(
            event_id=event.event_id,
            decision=decision,
            tool=request.tool,
            resource_authorization_event_id=(resource_result.event_id if resource_result else None),
            process_capability=(
                resource_result.capability
                if isinstance(resource_result, ProcessAuthorizationResult)
                and decision.decision is DecisionAction.ALLOW
                else None
            ),
        )

    def _validate_request(
        self,
        request: ToolAuthorizeRequest,
        verified_agent_id: str | None,
    ) -> tuple[DetectionFinding | None, ToolDefinition | None]:
        if verified_agent_id is None:
            return self._deny("ASEC-TOOL-IDENTITY-001", ReasonCode.AGENT_IDENTITY_UNVERIFIED), None
        definition = self._registry.get(request.tool)
        if definition is None:
            return self._deny("ASEC-TOOL-UNKNOWN-001", ReasonCode.TOOL_NOT_REGISTERED), None
        if verified_agent_id not in definition.allowed_agents:
            return self._deny("ASEC-TOOL-PERMISSION-001", ReasonCode.TOOL_NOT_ALLOWED), None
        errors = self._validator.validate(definition, request.arguments)
        if errors:
            return self._deny("ASEC-TOOL-ARGUMENT-001", ReasonCode.TOOL_ARGUMENT_INVALID), None
        if definition.capability is ToolCapability.FILESYSTEM and self._filesystem_firewall is None:
            return self._deny(
                "ASEC-TOOL-RESOURCE-MISSING-001",
                ReasonCode.RESOURCE_FIREWALL_UNAVAILABLE,
            ), None
        if definition.capability is ToolCapability.NETWORK and self._network_firewall is None:
            return self._deny(
                "ASEC-TOOL-RESOURCE-MISSING-001",
                ReasonCode.RESOURCE_FIREWALL_UNAVAILABLE,
            ), None
        required_firewalls = {
            ToolCapability.PROCESS: self._process_firewall,
            ToolCapability.DATABASE: self._database_firewall,
            ToolCapability.API: self._api_firewall,
        }
        if definition.capability in required_firewalls and required_firewalls[definition.capability] is None:
            return self._deny(
                "ASEC-TOOL-RESOURCE-MISSING-001",
                ReasonCode.RESOURCE_FIREWALL_UNAVAILABLE,
            ), None
        return None, definition

    def _authorize_resource(
        self,
        definition: ToolDefinition,
        request: ToolAuthorizeRequest,
        verified_agent_id: str | None,
    ) -> ResourceAuthorizationResult | ProcessAuthorizationResult | None:
        if definition.capability is ToolCapability.NONE:
            return None
        resource = request.arguments.get(definition.resource_argument or "")
        if definition.capability is ToolCapability.FILESYSTEM:
            if not isinstance(resource, str):
                raise ValueError("validated filesystem resource must be a string")
            if self._filesystem_firewall is None or definition.filesystem_operation is None:
                raise RuntimeError("filesystem firewall unavailable after validation")
            return self._filesystem_firewall.authorize(FilesystemAuthorizationRequest(
                path=resource,
                operation=definition.filesystem_operation,
                session_id=request.session_id,
            ))
        if definition.capability is ToolCapability.NETWORK:
            if not isinstance(resource, str):
                raise ValueError("validated network resource must be a string")
            if self._network_firewall is None:
                raise RuntimeError("network firewall unavailable after validation")
            return self._network_firewall.authorize(NetworkAuthorizationRequest(
                url=resource,
                session_id=request.session_id,
            ))
        if not isinstance(resource, dict):
            raise ValueError("validated structured resource must be an object")
        payload = {**resource, "session_id": request.session_id}
        if definition.capability is ToolCapability.PROCESS:
            if self._process_firewall is None:
                raise RuntimeError("process firewall unavailable after validation")
            return self._process_firewall.authorize(ProcessAuthorizationRequest.model_validate(payload))
        if definition.capability is ToolCapability.DATABASE:
            if self._database_firewall is None:
                raise RuntimeError("database firewall unavailable after validation")
            return self._database_firewall.authorize(
                DatabaseAuthorizationRequest.model_validate(payload),
                verified_agent_id=verified_agent_id,
            )
        if definition.capability is ToolCapability.API:
            if self._api_firewall is None:
                raise RuntimeError("API firewall unavailable after validation")
            return self._api_firewall.authorize(
                APIAuthorizationRequest.model_validate(payload),
                verified_agent_id=verified_agent_id,
            )
        raise RuntimeError("unsupported tool capability")

    def _decide(self, event: SecurityEvent, finding: DetectionFinding) -> SecurityDecision:
        context = SecurityContext(user_trust=TrustLevel.TRUSTED, agent_trust=event.trust_level)
        return decide_with_active_policy(
            event=event,
            context=context,
            findings=(finding,),
            risk_engine=self._risk_engine,
            policy_engine=self._policy_engine,
            policy_detector=self._policy_detector,
        )

    @staticmethod
    def _allow() -> DetectionFinding:
        return DetectionFinding(
            rule_id="ASEC-TOOL-GRANT-001",
            severity=Severity.INFO,
            risk_score=0,
            actions=(RuleAction.ALLOW, RuleAction.AUDIT),
            reason_codes=(ReasonCode.TOOL_AUTHORIZED.value,),
        )

    @staticmethod
    def _deny(
        rule_id: str,
        reason: ReasonCode,
        *,
        extra_reasons: tuple[str, ...] = (),
    ) -> DetectionFinding:
        return DetectionFinding(
            rule_id=rule_id,
            severity=Severity.CRITICAL,
            risk_score=100,
            actions=(RuleAction.DENY, RuleAction.AUDIT),
            reason_codes=(reason.value, *extra_reasons),
        )
