from collections.abc import Iterable

from core.context.models import SecurityContext
from core.contracts import DetectionEngineContract
from core.decisions.actions import DecisionAction
from core.decisions.models import SecurityDecision
from core.decisions.reasons import ReasonCode
from core.events.factory import SecurityEventFactory
from core.events.types import TrustLevel
from core.fingerprints import fingerprint_text
from core.risk.engine import RiskEngine
from detection.models import DetectionFinding, RuleAction, Severity
from output_security.contracts import (
    OutputRedactorContract,
    OutputSpanDetectorContract,
    SecretDetectorContract,
)
from output_security.internal_data import InternalDataDetector
from output_security.models import (
    OutputSource,
    OutputFinding,
    OutputScanRequest,
    OutputScanResult,
    OutputThreatCategory,
    SensitiveSpan,
)
from output_security.pii import PIIDetector
from output_security.redactor import OutputRedactor
from output_security.secrets import secret_spans
from output_security.urls import SensitiveURLDetector
from policy.engine import PolicyEngine
from policy.runtime import decide_with_active_policy
from secret_detection.detector import SecretDetector
from secret_detection.models import SecretCategory, SecretLocation
from telemetry.audit import StructuredAuditLogger


_REASON_BY_CATEGORY = {
    OutputThreatCategory.SECRET: ReasonCode.SECRET_DETECTED,
    OutputThreatCategory.PII: ReasonCode.PII_DETECTED,
    OutputThreatCategory.SENSITIVE_URL: ReasonCode.SENSITIVE_URL_DETECTED,
    OutputThreatCategory.INTERNAL_DATA: ReasonCode.INTERNAL_DATA_DETECTED,
}


class OutputGuard:
    def __init__(
        self,
        *,
        secret_detector: SecretDetectorContract | None = None,
        pii_detector: OutputSpanDetectorContract | None = None,
        url_detector: OutputSpanDetectorContract | None = None,
        internal_data_detector: OutputSpanDetectorContract | None = None,
        redactor: OutputRedactorContract | None = None,
        policy_detector: DetectionEngineContract | None = None,
        risk_engine: RiskEngine | None = None,
        policy_engine: PolicyEngine | None = None,
        audit_logger: StructuredAuditLogger | None = None,
        event_factory: SecurityEventFactory | None = None,
    ) -> None:
        self._secret_detector = secret_detector or SecretDetector()
        self._pii_detector = pii_detector or PIIDetector()
        self._url_detector = url_detector or SensitiveURLDetector()
        self._internal_data_detector = internal_data_detector or InternalDataDetector()
        self._redactor = redactor or OutputRedactor()
        self._policy_detector = policy_detector
        self._risk_engine = risk_engine or RiskEngine()
        self._policy_engine = policy_engine or PolicyEngine()
        self._audit_logger = audit_logger or StructuredAuditLogger()
        self._event_factory = event_factory or SecurityEventFactory()

    def scan(
        self,
        request: OutputScanRequest,
        *,
        source: OutputSource = OutputSource.LLM,
    ) -> OutputScanResult:
        output_fingerprint = fingerprint_text(request.output)
        event = self._event_factory.create(
            event_type="output.scan",
            source=source.value,
            action="scan",
            target="output_security",
            resource_type="llm_output",
            trust_level=TrustLevel.UNTRUSTED,
            session_id=request.session_id,
            user_id=request.user_id,
            data={
                "output_fingerprint": output_fingerprint,
                "output_length": len(request.output),
            },
        )
        findings: tuple[OutputFinding, ...] = ()
        released_output: str | None = None
        redaction_count = 0
        try:
            spans = self._detect(request.output)
            redacted, redaction_count = self._redactor.redact(request.output, spans)
            findings = tuple(self._to_finding(span) for span in spans)
            security_findings = self._security_findings(spans)
            context = SecurityContext(
                user_trust=TrustLevel.TRUSTED,
                agent_trust=TrustLevel.UNTRUSTED,
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
                "redaction_count": redaction_count,
            }})
            if decision.decision is DecisionAction.ALLOW:
                released_output = request.output
            elif decision.decision is DecisionAction.SANITIZE:
                released_output = redacted
        except Exception as exc:
            failure_fingerprint = fingerprint_text(type(exc).__name__)
            findings = (OutputFinding(
                code="OUTPUT_SECURITY_ENGINE_FAILURE",
                category=OutputThreatCategory.INTERNAL_SECURITY_ERROR,
                severity=Severity.CRITICAL,
                risk_score=100,
                detector="output_guard",
                evidence_fingerprint=failure_fingerprint,
                metadata={"error_type": type(exc).__name__},
            ),)
            decision = SecurityDecision(
                decision=DecisionAction.DENY,
                risk_score=100,
                reason_codes=(ReasonCode.OUTPUT_SECURITY_FAILURE,),
                metadata={"finding_codes": ["OUTPUT_SECURITY_ENGINE_FAILURE"]},
            )

        self._audit_logger.record(event, decision)
        return OutputScanResult(
            event_id=event.event_id,
            decision=decision,
            findings=findings,
            output_fingerprint=output_fingerprint,
            released_fingerprint=(fingerprint_text(released_output) if released_output is not None else None),
            output_length=len(request.output),
            released_length=len(released_output) if released_output is not None else 0,
            redaction_count=redaction_count,
            released_output=released_output,
        )

    def _detect(self, text: str) -> tuple[SensitiveSpan, ...]:
        spans = [
            *secret_spans(self._secret_detector.detect(
                text,
                location=SecretLocation.PRODUCTION_OUTPUT,
            )),
            *self._pii_detector.detect(text),
            *self._url_detector.detect(text),
            *self._internal_data_detector.detect(text),
        ]
        if any(
            span.start < 0
            or span.end <= span.start
            or span.end > len(text)
            for span in spans
        ):
            raise ValueError("output detector returned an invalid span")
        return tuple(sorted(spans, key=lambda item: (item.start, item.end, item.code)))

    @staticmethod
    def _to_finding(span: SensitiveSpan) -> OutputFinding:
        metadata = span.metadata or {}
        safe_metadata = {}
        if metadata.get("location") in {item.value for item in SecretLocation}:
            safe_metadata["location"] = metadata["location"]
        if metadata.get("secret_category") in {item.value for item in SecretCategory}:
            safe_metadata["secret_category"] = metadata["secret_category"]
        return OutputFinding(
            code=span.code,
            category=span.category,
            severity=span.severity,
            risk_score=span.risk_score,
            detector=span.detector,
            evidence_fingerprint=span.evidence_fingerprint,
            metadata=safe_metadata,
        )

    @staticmethod
    def _security_findings(spans: Iterable[SensitiveSpan]) -> tuple[DetectionFinding, ...]:
        grouped: dict[OutputThreatCategory, list[SensitiveSpan]] = {}
        for span in spans:
            grouped.setdefault(span.category, []).append(span)
        converted = [DetectionFinding(
            rule_id="ASEC-OUTPUT-BASELINE",
            severity=Severity.INFO,
            risk_score=0,
            actions=(RuleAction.ALLOW, RuleAction.AUDIT),
            reason_codes=(ReasonCode.OUTPUT_AUTHORIZED.value,) if not grouped else (),
        )]
        converted.extend(DetectionFinding(
            rule_id=f"ASEC-OUTPUT-{category.value}",
            severity=max(items, key=lambda item: item.risk_score).severity,
            risk_score=max(item.risk_score for item in items),
            actions=(RuleAction.SANITIZE, RuleAction.AUDIT),
            reason_codes=(
                _REASON_BY_CATEGORY[category].value,
                *(
                    (ReasonCode.OUTPUT_SANITIZED.value,)
                    if category is OutputThreatCategory.PII
                    else ()
                ),
            ),
        ) for category, items in sorted(grouped.items(), key=lambda item: item[0].value))
        return tuple(converted)
