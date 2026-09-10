from agent_security.identity import is_valid_identity
import re
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
from runtime.behavior.anomaly import RuntimeAnomalyDetector
from runtime.behavior.baseline import BehaviorBaseline
from runtime.behavior.profiles import BehaviorProfile
from runtime.models import (
    RuntimeEventRequest,
    RuntimeFinding,
    RuntimeObservation,
    RuntimeObservationResult,
    SessionInspectionResult,
)
from runtime.sessions.manager import SessionManager
from telemetry.audit import StructuredAuditLogger


_SESSION_ID = re.compile(r"^[A-Za-z0-9_.:-]{1,128}$")


class RuntimeMonitor:
    def __init__(
        self,
        profiles: tuple[BehaviorProfile, ...] = (),
        *,
        baseline: BehaviorBaseline | None = None,
        session_manager: SessionManager | None = None,
        anomaly_detector: RuntimeAnomalyDetector | None = None,
        policy_detector: DetectionEngineContract | None = None,
        risk_engine: RiskEngine | None = None,
        policy_engine: PolicyEngine | None = None,
        audit_logger: StructuredAuditLogger | None = None,
        event_factory: SecurityEventFactory | None = None,
    ) -> None:
        self._baseline = baseline or BehaviorBaseline(profiles)
        self._sessions = session_manager or SessionManager()
        self._detector = anomaly_detector or RuntimeAnomalyDetector()
        self._policy_detector = policy_detector
        self._risk_engine = risk_engine or RiskEngine()
        self._policy_engine = policy_engine or PolicyEngine()
        self._audit_logger = audit_logger or StructuredAuditLogger()
        self._event_factory = event_factory or SecurityEventFactory()

    def observe(
        self,
        request: RuntimeEventRequest,
        *,
        verified_agent_id: str | None = None,
    ) -> RuntimeObservationResult:
        identity_valid = is_valid_identity(verified_agent_id)
        agent_id = verified_agent_id if identity_valid else None
        event = self._event_factory.create(
            event_type="runtime.observe",
            source="runtime_collector",
            action=request.activity.value,
            target="runtime_monitor",
            resource_type="runtime_activity",
            trust_level=TrustLevel.TRUSTED if identity_valid else TrustLevel.UNKNOWN,
            session_id=request.session_id,
            agent_id=agent_id,
            data={
                "activity": request.activity.value,
                "outcome": request.outcome.value,
                "has_target_fingerprint": request.target_fingerprint is not None,
                "source_event_fingerprint": fingerprint_text(
                    request.source_event_id or "none"
                ),
            },
        )
        findings: tuple[RuntimeFinding, ...] = ()
        event_count = 0
        try:
            profile = self._baseline.get(agent_id or "")
            if agent_id is None:
                findings = (_finding(
                    "RUNTIME_UNVERIFIED_IDENTITY",
                    ReasonCode.RUNTIME_IDENTITY_UNVERIFIED,
                    100,
                ),)
            elif profile is None:
                findings = (_finding(
                    "RUNTIME_PROFILE_NOT_FOUND",
                    ReasonCode.RUNTIME_PROFILE_MISSING,
                    100,
                ),)
            else:
                observation = RuntimeObservation(
                    runtime_event_id=event.event_id,
                    source_event_id=request.source_event_id,
                    timestamp=event.timestamp,
                    session_id=request.session_id,
                    agent_id=agent_id,
                    activity=request.activity,
                    outcome=request.outcome,
                    target_fingerprint=request.target_fingerprint,
                )
                findings, event_count, failure = self._sessions.observe(
                    observation,
                    lambda items: self._detector.detect(items, profile),
                )
                if failure is not None:
                    findings = (_finding(
                        f"RUNTIME_{failure.value}",
                        failure,
                        100,
                    ),)
            decision = self._decide(event, findings)
        except Exception:
            decision = SecurityDecision(
                decision=DecisionAction.DENY,
                risk_score=100,
                reason_codes=(ReasonCode.UNKNOWN_SECURITY_STATE,),
            )
            findings = ()
            event_count = 0
        self._audit_logger.record(event, decision)
        return RuntimeObservationResult(
            event_id=event.event_id,
            decision=decision,
            findings=findings,
            session_event_count=event_count,
        )

    def inspect_session(
        self,
        session_id: str,
        *,
        verified_agent_id: str | None = None,
    ) -> SessionInspectionResult:
        identity_valid = is_valid_identity(verified_agent_id)
        agent_id = verified_agent_id if identity_valid else None
        session_valid = isinstance(session_id, str) and _SESSION_ID.fullmatch(session_id) is not None
        event = self._event_factory.create(
            event_type="runtime.session.inspect",
            source="runtime_api",
            action="inspect",
            target="runtime_session",
            resource_type="session",
            trust_level=TrustLevel.TRUSTED if identity_valid else TrustLevel.UNKNOWN,
            session_id=session_id if session_valid else None,
            agent_id=agent_id,
            data={
                "session_fingerprint": fingerprint_text(
                    session_id if session_valid else "invalid-session"
                ),
                "agent_fingerprint": fingerprint_text(agent_id or "unverified"),
            },
        )
        summary = None
        try:
            if not session_valid:
                reason = ReasonCode.RUNTIME_SESSION_INVALID
            elif agent_id is None:
                reason = ReasonCode.RUNTIME_IDENTITY_UNVERIFIED
            else:
                summary, reason = self._sessions.inspect(session_id, agent_id)
            decision = self._decide_reason(
                event,
                ReasonCode.RUNTIME_SESSION_INSPECTED if reason is None else reason,
                allow=reason is None,
            )
        except Exception:
            decision = self._decide_reason(event, ReasonCode.UNKNOWN_SECURITY_STATE, allow=False)
            summary = None
        self._audit_logger.record(event, decision)
        return SessionInspectionResult(
            event_id=event.event_id,
            decision=decision,
            summary=summary if decision.decision is DecisionAction.ALLOW else None,
        )

    def _decide(
        self,
        event: SecurityEvent,
        findings: tuple[RuntimeFinding, ...],
    ) -> SecurityDecision:
        security_findings = tuple(
            DetectionFinding(
                rule_id=f"ASEC-RUNTIME-{finding.code}",
                severity=finding.severity,
                risk_score=finding.risk_score,
                actions=(
                    RuleAction.DENY
                    if finding.risk_score >= 80
                    else RuleAction.APPROVAL_REQUIRED,
                    RuleAction.AUDIT,
                ),
                reason_codes=(finding.reason_code,),
            )
            for finding in findings
        )
        if not security_findings:
            security_findings = (DetectionFinding(
                rule_id="ASEC-RUNTIME-BASELINE",
                severity=Severity.INFO,
                risk_score=0,
                actions=(RuleAction.ALLOW, RuleAction.AUDIT),
                reason_codes=(ReasonCode.RUNTIME_EVENT_ACCEPTED.value,),
            ),)
        context = SecurityContext(
            user_trust=TrustLevel.TRUSTED,
            agent_trust=event.trust_level,
        )
        return decide_with_active_policy(
            event=event,
            context=context,
            findings=security_findings,
            risk_engine=self._risk_engine,
            policy_engine=self._policy_engine,
            policy_detector=self._policy_detector,
        )

    def _decide_reason(
        self,
        event: SecurityEvent,
        reason: ReasonCode,
        *,
        allow: bool,
    ) -> SecurityDecision:
        finding = DetectionFinding(
            rule_id="ASEC-RUNTIME-SESSION-001",
            severity=Severity.INFO if allow else Severity.CRITICAL,
            risk_score=0 if allow else 100,
            actions=(RuleAction.ALLOW if allow else RuleAction.DENY, RuleAction.AUDIT),
            reason_codes=(reason.value,),
        )
        context = SecurityContext(
            user_trust=TrustLevel.TRUSTED,
            agent_trust=event.trust_level,
        )
        return decide_with_active_policy(
            event=event,
            context=context,
            findings=(finding,),
            risk_engine=self._risk_engine,
            policy_engine=self._policy_engine,
            policy_detector=self._policy_detector,
        )


def _finding(code: str, reason: ReasonCode, risk_score: int) -> RuntimeFinding:
    return RuntimeFinding(
        code=code,
        severity=Severity.CRITICAL if risk_score >= 80 else Severity.HIGH,
        risk_score=risk_score,
        reason_code=reason.value,
    )

