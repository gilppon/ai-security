from pathlib import Path

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
from resource_security.filesystem.models import FilesystemAuthorizationRequest, FilesystemGrant
from resource_security.filesystem.paths import containing_root, resolve_candidate
from resource_security.filesystem.sensitive import is_sensitive_path
from resource_security.models import ResourceAuthorizationResult
from telemetry.audit import StructuredAuditLogger


class FilesystemFirewall:
    def __init__(
        self,
        grants: tuple[FilesystemGrant, ...] = (),
        *,
        risk_engine: RiskEngine | None = None,
        policy_engine: PolicyEngine | None = None,
        audit_logger: StructuredAuditLogger | None = None,
        event_factory: SecurityEventFactory | None = None,
    ) -> None:
        merged: dict[Path, set] = {}
        for grant in grants:
            root = grant.root.resolve(strict=False)
            merged.setdefault(root, set()).update(grant.operations)
        self._grants = tuple(
            FilesystemGrant(root=root, operations=frozenset(operations))
            for root, operations in sorted(merged.items(), key=lambda item: str(item[0]).casefold())
        )
        self._roots = tuple(grant.root for grant in self._grants)
        self._risk_engine = risk_engine or RiskEngine()
        self._policy_engine = policy_engine or PolicyEngine()
        self._audit_logger = audit_logger or StructuredAuditLogger()
        self._event_factory = event_factory or SecurityEventFactory()

    def authorize(self, request: FilesystemAuthorizationRequest) -> ResourceAuthorizationResult:
        event = self._event_factory.create(
            event_type="filesystem.authorize",
            source="resource_firewall",
            action=request.operation.value,
            target="filesystem",
            resource_type="path",
            trust_level=TrustLevel.TRUSTED,
            session_id=request.session_id,
            data={"path_fingerprint": fingerprint_text(request.path), "operation": request.operation.value},
        )
        resolved: Path | None = None
        try:
            base_root = self._roots[0] if len(self._roots) == 1 else None
            resolved = resolve_candidate(request.path, base_root)
            root = containing_root(resolved, self._roots)
            if root is None:
                finding = self._finding(
                    "ASEC-FS-PATH-OUTSIDE-001",
                    ReasonCode.PATH_OUTSIDE_ALLOWED_ROOT,
                    deny=True,
                )
            elif is_sensitive_path(resolved):
                finding = self._finding("ASEC-FS-SENSITIVE-001", ReasonCode.SENSITIVE_PATH, deny=True)
            else:
                grant = next(item for item in self._grants if item.root == root)
                if request.operation not in grant.operations:
                    finding = self._finding(
                        "ASEC-FS-OPERATION-001",
                        ReasonCode.FILESYSTEM_OPERATION_NOT_ALLOWED,
                        deny=True,
                    )
                else:
                    finding = self._finding(
                        "ASEC-FS-GRANT-001",
                        ReasonCode.FILESYSTEM_AUTHORIZED,
                        deny=False,
                    )
            decision = self._decide(event, finding)
        except (OSError, RuntimeError, ValueError):
            decision = SecurityDecision(
                decision=DecisionAction.DENY,
                risk_score=100,
                reason_codes=(ReasonCode.INVALID_PATH,),
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
                str(resolved)
                if resolved is not None and decision.decision is DecisionAction.ALLOW
                else None
            ),
        )

    def _decide(self, event: SecurityEvent, finding: DetectionFinding) -> SecurityDecision:
        context = SecurityContext(user_trust=TrustLevel.TRUSTED, agent_trust=TrustLevel.TRUSTED)
        risk = self._risk_engine.score(event, context, (finding,))
        return self._policy_engine.decide(risk, (finding,))

    @staticmethod
    def _finding(rule_id: str, reason: ReasonCode, *, deny: bool) -> DetectionFinding:
        return DetectionFinding(
            rule_id=rule_id,
            severity=Severity.CRITICAL if deny else Severity.INFO,
            risk_score=100 if deny else 0,
            actions=(RuleAction.DENY if deny else RuleAction.ALLOW, RuleAction.AUDIT),
            reason_codes=(reason.value,),
        )
