from ipaddress import ip_address
from urllib.parse import urlsplit

from core.context.models import SecurityContext
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
from resource_security.models import ResourceAuthorizationResult
from resource_security.network.dns import DNSResolver, IPAddress, SystemDNSResolver
from resource_security.network.ip_policy import blocked_ip_reason
from resource_security.network.models import NetworkAuthorizationRequest, NetworkGrant
from telemetry.audit import StructuredAuditLogger


class NetworkFirewall:
    def __init__(
        self,
        grants: tuple[NetworkGrant, ...] = (),
        *,
        resolver: DNSResolver | None = None,
        risk_engine: RiskEngine | None = None,
        policy_engine: PolicyEngine | None = None,
        audit_logger: StructuredAuditLogger | None = None,
        event_factory: SecurityEventFactory | None = None,
    ) -> None:
        self._grants = grants
        self._resolver = resolver or SystemDNSResolver()
        self._risk_engine = risk_engine or RiskEngine()
        self._policy_engine = policy_engine or PolicyEngine()
        self._audit_logger = audit_logger or StructuredAuditLogger()
        self._event_factory = event_factory or SecurityEventFactory()

    def authorize(self, request: NetworkAuthorizationRequest) -> ResourceAuthorizationResult:
        event = self._event_factory.create(
            event_type="network.authorize",
            source="resource_firewall",
            action="connect",
            target="network",
            resource_type="url",
            trust_level=TrustLevel.TRUSTED,
            session_id=request.session_id,
            data={"url_fingerprint": fingerprint_text(request.url)},
        )
        normalized_resource: str | None = None
        addresses: tuple[IPAddress, ...] = ()
        try:
            if request.url != request.url.strip() or any(ord(character) < 32 for character in request.url):
                raise ValueError("URL contains invalid characters")
            parsed = urlsplit(request.url)
            if parsed.scheme.casefold() != "https":
                finding = self._deny("ASEC-NET-SCHEME-001", ReasonCode.NETWORK_SCHEME_DENIED)
            elif parsed.username is not None or parsed.password is not None:
                finding = self._deny("ASEC-NET-CREDENTIALS-001", ReasonCode.NETWORK_CREDENTIALS_DENIED)
            elif not parsed.hostname:
                finding = self._deny("ASEC-NET-INVALID-001", ReasonCode.INVALID_NETWORK_DESTINATION)
            else:
                hostname = parsed.hostname.casefold().rstrip(".").encode("idna").decode("ascii")
                port = parsed.port or 443
                grant = self._matching_grant(hostname, port)
                if grant is None:
                    finding = self._deny("ASEC-NET-HOST-001", ReasonCode.NETWORK_HOST_DENIED)
                else:
                    addresses = self._resolve(hostname)
                    if not addresses:
                        finding = self._deny("ASEC-NET-DNS-001", ReasonCode.DNS_RESOLUTION_FAILED)
                    else:
                        blocked = next(
                            (reason for address in addresses if (reason := blocked_ip_reason(address))),
                            None,
                        )
                        if blocked == ReasonCode.METADATA_ENDPOINT.value:
                            finding = self._deny("ASEC-NET-METADATA-001", ReasonCode.METADATA_ENDPOINT)
                        elif blocked:
                            finding = self._deny("ASEC-NET-PRIVATE-001", ReasonCode.PRIVATE_NETWORK_DESTINATION)
                        else:
                            finding = DetectionFinding(
                                rule_id="ASEC-NET-GRANT-001",
                                severity=Severity.INFO,
                                risk_score=0,
                                actions=(RuleAction.ALLOW, RuleAction.AUDIT),
                                reason_codes=(
                                    ReasonCode.NETWORK_AUTHORIZED.value,
                                    ReasonCode.REDIRECT_REAUTHORIZATION_REQUIRED.value,
                                ),
                            )
                            pinned_address = addresses[0]
                            address_display = f"[{pinned_address}]" if pinned_address.version == 6 else str(pinned_address)
                            normalized_resource = f"https://{address_display}:{port}"
            decision = self._decide(event, finding)
        except (UnicodeError, ValueError):
            decision = SecurityDecision(
                decision=DecisionAction.DENY,
                risk_score=100,
                reason_codes=(ReasonCode.INVALID_NETWORK_DESTINATION,),
            )
        except OSError:
            decision = SecurityDecision(
                decision=DecisionAction.DENY,
                risk_score=100,
                reason_codes=(ReasonCode.DNS_RESOLUTION_FAILED,),
            )
        except Exception:
            decision = SecurityDecision(
                decision=DecisionAction.DENY,
                risk_score=100,
                reason_codes=(ReasonCode.UNKNOWN_SECURITY_STATE,),
            )

        self._audit_logger.record(event, decision)
        allowed = decision.decision is DecisionAction.ALLOW
        return ResourceAuthorizationResult(
            event_id=event.event_id,
            decision=decision,
            normalized_resource=normalized_resource if allowed else None,
            resolved_addresses=tuple(str(address) for address in addresses) if allowed else (),
            redirect_reauthorization_required=allowed,
        )

    def authorize_redirect(self, target_url: str, *, session_id: str | None = None) -> ResourceAuthorizationResult:
        return self.authorize(NetworkAuthorizationRequest(url=target_url, session_id=session_id))

    def _resolve(self, hostname: str) -> tuple[IPAddress, ...]:
        try:
            return (ip_address(hostname),)
        except ValueError:
            addresses = set(self._resolver.resolve(hostname))
            return tuple(sorted(addresses, key=lambda item: (item.version, int(item))))

    def _matching_grant(self, hostname: str, port: int) -> NetworkGrant | None:
        return next(
            (
                grant
                for grant in self._grants
                if port in grant.ports and self._host_matches(hostname, grant.host_pattern)
            ),
            None,
        )

    @staticmethod
    def _host_matches(hostname: str, pattern: str) -> bool:
        if pattern.startswith("*."):
            suffix = pattern[1:]
            return hostname.endswith(suffix) and hostname != pattern[2:]
        return hostname == pattern

    def _decide(self, event: SecurityEvent, finding: DetectionFinding) -> SecurityDecision:
        context = SecurityContext(user_trust=TrustLevel.TRUSTED, agent_trust=TrustLevel.TRUSTED)
        risk = self._risk_engine.score(event, context, (finding,))
        return self._policy_engine.decide(risk, (finding,))

    @staticmethod
    def _deny(rule_id: str, reason: ReasonCode) -> DetectionFinding:
        return DetectionFinding(
            rule_id=rule_id,
            severity=Severity.CRITICAL,
            risk_score=100,
            actions=(RuleAction.DENY, RuleAction.AUDIT),
            reason_codes=(reason.value,),
        )
