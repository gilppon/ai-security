from urllib.parse import parse_qsl, urlsplit

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
from resource_security.api.models import APIAuthorizationRequest, APIEndpointGrant
from resource_security.contracts import NetworkAuthorizer
from resource_security.models import ResourceAuthorizationResult
from resource_security.network.models import NetworkAuthorizationRequest
from telemetry.audit import StructuredAuditLogger
from agent_security.identity import is_valid_identity


class APIFirewall:
    def __init__(
        self,
        grants: tuple[APIEndpointGrant, ...] = (),
        *,
        network_firewall: NetworkAuthorizer | None = None,
        policy_detector: DetectionEngineContract | None = None,
        risk_engine: RiskEngine | None = None,
        policy_engine: PolicyEngine | None = None,
        audit_logger: StructuredAuditLogger | None = None,
        event_factory: SecurityEventFactory | None = None,
    ) -> None:
        self._grants = {grant.api_id: grant for grant in grants}
        if len(self._grants) != len(grants):
            raise ValueError("API endpoint grants must have unique ids")
        self._network_firewall = network_firewall
        self._policy_detector = policy_detector
        self._risk_engine = risk_engine or RiskEngine()
        self._policy_engine = policy_engine or PolicyEngine()
        self._audit_logger = audit_logger or StructuredAuditLogger()
        self._event_factory = event_factory or SecurityEventFactory()

    def authorize(
        self,
        request: APIAuthorizationRequest,
        *,
        verified_agent_id: str | None = None,
    ) -> ResourceAuthorizationResult:
        event = self._event_factory.create(
            event_type="api.authorize",
            source="resource_firewall",
            action=request.method.value,
            target="api",
            resource_type="api_endpoint",
            trust_level=TrustLevel.TRUSTED if verified_agent_id else TrustLevel.UNKNOWN,
            session_id=request.session_id,
            agent_id=verified_agent_id,
            data={
                "api_fingerprint": fingerprint_text(request.api_id),
                "url_fingerprint": fingerprint_text(request.url),
                "body_field_count": len(request.body_fields),
            },
        )
        network_result: ResourceAuthorizationResult | None = None
        grant: APIEndpointGrant | None = None
        try:
            finding, grant = self._validate(request, verified_agent_id)
            if grant is not None:
                if self._network_firewall is None:
                    finding = self._finding(
                        "ASEC-API-NETWORK-MISSING-001", ReasonCode.RESOURCE_FIREWALL_UNAVAILABLE, True
                    )
                else:
                    network_result = self._network_firewall.authorize(NetworkAuthorizationRequest(
                        url=request.url,
                        session_id=request.session_id,
                    ))
                    if network_result.decision.decision is not DecisionAction.ALLOW:
                        finding = self._finding(
                            "ASEC-API-NETWORK-001",
                            ReasonCode.API_NETWORK_DENIED,
                            True,
                            extra_reasons=tuple(
                                reason.value for reason in network_result.decision.reason_codes
                            ),
                        )
            decision = self._decide(event, finding)
        except (TypeError, ValueError):
            decision = SecurityDecision(
                decision=DecisionAction.DENY,
                risk_score=100,
                reason_codes=(ReasonCode.API_PATH_DENIED,),
            )
        except Exception:
            decision = SecurityDecision(
                decision=DecisionAction.DENY,
                risk_score=100,
                reason_codes=(ReasonCode.UNKNOWN_SECURITY_STATE,),
            )
        self._audit_logger.record(event, decision)
        return ResourceAuthorizationResult(
            event_id=event.event_id,
            decision=decision,
            normalized_resource=(
                f"{request.api_id}:{grant.path}"
                if grant is not None and decision.decision is DecisionAction.ALLOW else None
            ),
            resolved_addresses=(network_result.resolved_addresses if network_result else ()),
        )

    def _validate(
        self,
        request: APIAuthorizationRequest,
        agent_id: str | None,
    ) -> tuple[DetectionFinding, APIEndpointGrant | None]:
        if not is_valid_identity(agent_id):
            return self._finding("ASEC-API-IDENTITY-001", ReasonCode.API_IDENTITY_UNVERIFIED, True), None
        grant = self._grants.get(request.api_id)
        if grant is None or agent_id not in grant.allowed_agents:
            return self._finding("ASEC-API-ENDPOINT-001", ReasonCode.API_ENDPOINT_UNKNOWN, True), None
        if request.method is not grant.method:
            return self._finding("ASEC-API-METHOD-001", ReasonCode.API_METHOD_DENIED, True), None
        requested = urlsplit(request.url)
        origin = urlsplit(grant.origin)
        requested_port = requested.port or (443 if requested.scheme.casefold() == "https" else 80)
        origin_port = origin.port or (443 if origin.scheme.casefold() == "https" else 80)
        if (
            requested.username is not None
            or requested.password is not None
            or requested.scheme.casefold() != origin.scheme.casefold()
            or (requested.hostname or "").casefold().rstrip(".") != (origin.hostname or "").casefold().rstrip(".")
            or requested_port != origin_port
            or requested.path != grant.path
            or requested.fragment
        ):
            return self._finding("ASEC-API-PATH-001", ReasonCode.API_PATH_DENIED, True), None
        query_names = {name for name, _ in parse_qsl(requested.query, keep_blank_values=True)}
        if not query_names.issubset(grant.allowed_query_parameters):
            return self._finding("ASEC-API-QUERY-001", ReasonCode.API_ARGUMENT_DENIED, True), None
        if not set(request.body_fields).issubset(grant.allowed_body_fields):
            return self._finding("ASEC-API-BODY-001", ReasonCode.API_ARGUMENT_DENIED, True), None
        return self._finding("ASEC-API-GRANT-001", ReasonCode.API_AUTHORIZED, False), grant

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
    def _finding(
        rule_id: str,
        reason: ReasonCode,
        deny: bool,
        *,
        extra_reasons: tuple[str, ...] = (),
    ) -> DetectionFinding:
        return DetectionFinding(
            rule_id=rule_id,
            severity=Severity.CRITICAL if deny else Severity.INFO,
            risk_score=100 if deny else 0,
            actions=(RuleAction.DENY if deny else RuleAction.ALLOW, RuleAction.AUDIT),
            reason_codes=(reason.value, *extra_reasons),
        )
