from collections.abc import Iterable

from core.context.models import SecurityContext
from core.contracts import DetectionEngineContract
from core.decisions.actions import DecisionAction
from core.decisions.models import SecurityDecision
from core.decisions.reasons import ReasonCode
from core.events.factory import SecurityEventFactory
from core.events.types import TrustLevel
from core.risk.engine import RiskEngine
from content_security.contracts import (
    ContextIsolationContract,
    DocumentScannerContract,
    SourceTrustEngineContract,
)
from content_security.document.scanner import DocumentScanner
from content_security.models import (
    ContentFinding,
    ContentScanRequest,
    ContentScanResult,
    ContentThreatCategory,
)
from content_security.rag.context_isolation import ContextIsolation
from content_security.source_trust.engine import SourceTrustEngine
from content_security.source_trust.models import SourceTrustAssessment
from content_security.utils import fingerprint
from detection.models import DetectionFinding, RuleAction, Severity
from policy.engine import PolicyEngine
from policy.runtime import decide_with_active_policy
from telemetry.audit import StructuredAuditLogger


class ContentFirewall:
    def __init__(
        self,
        *,
        scanner: DocumentScannerContract | None = None,
        source_trust_engine: SourceTrustEngineContract | None = None,
        policy_detector: DetectionEngineContract | None = None,
        risk_engine: RiskEngine | None = None,
        policy_engine: PolicyEngine | None = None,
        context_isolation: ContextIsolationContract | None = None,
        audit_logger: StructuredAuditLogger | None = None,
        event_factory: SecurityEventFactory | None = None,
    ) -> None:
        self._scanner = scanner or DocumentScanner()
        self._source_trust_engine = source_trust_engine or SourceTrustEngine()
        self._policy_detector = policy_detector
        self._risk_engine = risk_engine or RiskEngine()
        self._policy_engine = policy_engine or PolicyEngine()
        self._context_isolation = context_isolation or ContextIsolation()
        self._audit_logger = audit_logger or StructuredAuditLogger()
        self._event_factory = event_factory or SecurityEventFactory()

    def scan(
        self,
        request: ContentScanRequest,
        *,
        verified_source_trust: TrustLevel | None = None,
    ) -> ContentScanResult:
        content_fingerprint = fingerprint(request.content)
        assessment = SourceTrustAssessment(
            trust_level=TrustLevel.UNKNOWN,
            risk_score=100,
            reason_code="SOURCE_UNKNOWN",
        )
        event = self._event_factory.create(
            event_type="content.scan",
            source="external_content",
            action="scan",
            target="content_security",
            resource_type=request.content_type.value,
            trust_level=assessment.trust_level,
            session_id=request.session_id,
            data={
                "content_fingerprint": content_fingerprint,
                "content_length": len(request.content),
                "content_type": request.content_type.value,
                "source_type": request.source_type.value,
            },
        )
        findings: tuple[ContentFinding, ...] = ()
        sanitized = ""

        try:
            assessment = self._source_trust_engine.assess(
                request.source_type,
                verified_trust=verified_source_trust,
            )
            event = event.model_copy(update={"trust_level": assessment.trust_level})
            document = self._scanner.scan(request.content, request.content_type)
            sanitized = document.sanitized_content
            source_finding = self._source_finding(request, assessment)
            findings = tuple(sorted(
                (*document.findings, source_finding),
                key=lambda item: (item.code, item.evidence_fingerprint),
            ))
            security_findings = self._security_findings(findings)
            context = SecurityContext(
                user_trust=TrustLevel.TRUSTED,
                agent_trust=TrustLevel.TRUSTED,
            )
            decision = decide_with_active_policy(
                event=event,
                context=context,
                findings=security_findings,
                risk_engine=self._risk_engine,
                policy_engine=self._policy_engine,
                policy_detector=self._policy_detector,
            )
            decision = decision.model_copy(update={"metadata": {
                "finding_codes": [finding.code for finding in findings],
                "source_trust": assessment.trust_level.value,
                "sanitization_changed": sanitized != request.content,
            }})
        except Exception as exc:
            failure = ContentFinding(
                code="CONTENT_SECURITY_ENGINE_FAILURE",
                category=ContentThreatCategory.INTERNAL_SECURITY_ERROR,
                severity=Severity.CRITICAL,
                risk_score=100,
                detector="content_firewall",
                evidence_fingerprint=fingerprint(type(exc).__name__),
                metadata={"error_type": type(exc).__name__},
            )
            findings = (failure,)
            sanitized = ""
            decision = SecurityDecision(
                decision=DecisionAction.DENY,
                risk_score=100,
                reason_codes=(ReasonCode.UNKNOWN_SECURITY_STATE,),
                metadata={"finding_codes": [failure.code]},
            )

        self._audit_logger.record(event, decision)
        context_envelope = self._context_isolation.release(
            sanitized_content=sanitized,
            event_id=event.event_id,
            decision=decision.decision,
            source_trust=assessment.trust_level,
        )
        return ContentScanResult(
            event_id=event.event_id,
            decision=decision,
            findings=findings,
            source_trust=assessment.trust_level,
            content_fingerprint=content_fingerprint,
            sanitized_fingerprint=fingerprint(sanitized),
            sanitization_changed=sanitized != request.content,
            input_length=len(request.content),
            sanitized_length=len(sanitized),
            context=context_envelope,
        )

    @staticmethod
    def _source_finding(
        request: ContentScanRequest,
        assessment: SourceTrustAssessment,
    ) -> ContentFinding:
        severity = {
            TrustLevel.TRUSTED: Severity.INFO,
            TrustLevel.LIMITED: Severity.LOW,
            TrustLevel.UNTRUSTED: Severity.MEDIUM,
            TrustLevel.UNKNOWN: Severity.CRITICAL,
        }[assessment.trust_level]
        return ContentFinding(
            code=assessment.reason_code,
            category=ContentThreatCategory.SOURCE_TRUST,
            severity=severity,
            risk_score=assessment.risk_score,
            detector="source_trust_engine",
            evidence_fingerprint=fingerprint(request.source_type.value),
        )

    @staticmethod
    def _security_findings(findings: Iterable[ContentFinding]) -> tuple[DetectionFinding, ...]:
        converted = [DetectionFinding(
            rule_id="ASEC-CONTENT-BASELINE",
            severity=Severity.INFO,
            risk_score=0,
            actions=(RuleAction.ALLOW, RuleAction.AUDIT),
        )]
        converted.extend(
            DetectionFinding(
                rule_id=f"ASEC-CONTENT-{finding.code}",
                severity=finding.severity,
                risk_score=finding.risk_score,
                actions=(RuleAction.AUDIT,),
                reason_codes=(finding.code,),
            )
            for finding in findings
        )
        return tuple(converted)
