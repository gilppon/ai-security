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
from resource_security.database.models import DatabaseAuthorizationRequest, DatabaseGrant
from resource_security.models import ResourceAuthorizationResult
from telemetry.audit import StructuredAuditLogger
from agent_security.identity import is_valid_identity


class DatabaseFirewall:
    def __init__(
        self,
        grants: tuple[DatabaseGrant, ...] = (),
        *,
        risk_engine: RiskEngine | None = None,
        policy_engine: PolicyEngine | None = None,
        audit_logger: StructuredAuditLogger | None = None,
        event_factory: SecurityEventFactory | None = None,
    ) -> None:
        self._grants = {grant.database_id: grant for grant in grants}
        if len(self._grants) != len(grants):
            raise ValueError("database grants must have unique ids")
        self._risk_engine = risk_engine or RiskEngine()
        self._policy_engine = policy_engine or PolicyEngine()
        self._audit_logger = audit_logger or StructuredAuditLogger()
        self._event_factory = event_factory or SecurityEventFactory()

    def authorize(
        self,
        request: DatabaseAuthorizationRequest,
        *,
        verified_agent_id: str | None = None,
    ) -> ResourceAuthorizationResult:
        event = self._event_factory.create(
            event_type="database.authorize",
            source="resource_firewall",
            action=request.operation.value,
            target="database",
            resource_type="structured_query",
            trust_level=TrustLevel.TRUSTED if verified_agent_id else TrustLevel.UNKNOWN,
            session_id=request.session_id,
            agent_id=verified_agent_id,
            data={
                "database_fingerprint": fingerprint_text(request.database_id),
                "table_fingerprint": fingerprint_text(request.table),
                "column_count": len(request.columns),
                "predicate_count": len(request.predicate_fields),
            },
        )
        try:
            finding = self._validate(request, verified_agent_id)
            decision = self._decide(event, finding)
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
                f"{request.database_id}:{request.table}"
                if decision.decision is DecisionAction.ALLOW else None
            ),
        )

    def _validate(
        self,
        request: DatabaseAuthorizationRequest,
        agent_id: str | None,
    ) -> DetectionFinding:
        if not is_valid_identity(agent_id):
            return self._finding("ASEC-DB-IDENTITY-001", ReasonCode.DATABASE_IDENTITY_UNVERIFIED, True)
        grant = self._grants.get(request.database_id)
        if grant is None or agent_id not in grant.allowed_agents:
            return self._finding("ASEC-DB-DATABASE-001", ReasonCode.DATABASE_NOT_REGISTERED, True)
        table = next((item for item in grant.tables if item.table == request.table), None)
        if table is None:
            return self._finding("ASEC-DB-TABLE-001", ReasonCode.DATABASE_TABLE_DENIED, True)
        if request.operation not in table.operations:
            return self._finding("ASEC-DB-OPERATION-001", ReasonCode.DATABASE_OPERATION_DENIED, True)
        if not set(request.columns).issubset(table.columns):
            return self._finding("ASEC-DB-COLUMN-001", ReasonCode.DATABASE_COLUMN_DENIED, True)
        if not set(request.predicate_fields).issubset(table.predicate_fields):
            return self._finding("ASEC-DB-PREDICATE-001", ReasonCode.DATABASE_COLUMN_DENIED, True)
        return self._finding("ASEC-DB-GRANT-001", ReasonCode.DATABASE_AUTHORIZED, False)

    def _decide(self, event: SecurityEvent, finding: DetectionFinding) -> SecurityDecision:
        context = SecurityContext(user_trust=TrustLevel.TRUSTED, agent_trust=event.trust_level)
        return self._policy_engine.decide(self._risk_engine.score(event, context, (finding,)), (finding,))

    @staticmethod
    def _finding(rule_id: str, reason: ReasonCode, deny: bool) -> DetectionFinding:
        return DetectionFinding(
            rule_id=rule_id,
            severity=Severity.CRITICAL if deny else Severity.INFO,
            risk_score=100 if deny else 0,
            actions=(RuleAction.DENY if deny else RuleAction.ALLOW, RuleAction.AUDIT),
            reason_codes=(reason.value,),
        )
