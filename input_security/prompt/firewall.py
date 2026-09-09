from collections.abc import Iterable

from core.context.models import SecurityContext
from core.decisions.actions import DecisionAction
from core.decisions.models import SecurityDecision
from core.decisions.reasons import ReasonCode
from core.events.factory import SecurityEventFactory
from core.events.types import TrustLevel
from core.risk.engine import RiskEngine
from detection.models import DetectionFinding, RuleAction, Severity
from input_security.jailbreak.detector import JailbreakDetector
from input_security.prompt.contracts import (
    PromptNormalizerContract,
    PromptObfuscationDetectorContract,
    PromptTextDetectorContract,
)
from input_security.prompt.encoding import EncodingDetector
from input_security.prompt.models import (
    PromptFinding,
    PromptScanRequest,
    PromptScanResult,
    PromptThreatCategory,
)
from input_security.prompt.normalizer import PromptNormalizationResult, PromptNormalizer
from input_security.prompt.obfuscation import ObfuscationDetector
from input_security.prompt.rules import PromptRuleDetector
from input_security.prompt.utils import fingerprint
from policy.engine import PolicyEngine
from telemetry.audit import StructuredAuditLogger


class PromptFirewall:
    def __init__(
        self,
        *,
        normalizer: PromptNormalizerContract | None = None,
        rule_detector: PromptTextDetectorContract | None = None,
        encoding_detector: PromptTextDetectorContract | None = None,
        obfuscation_detector: PromptObfuscationDetectorContract | None = None,
        jailbreak_detector: PromptTextDetectorContract | None = None,
        risk_engine: RiskEngine | None = None,
        policy_engine: PolicyEngine | None = None,
        audit_logger: StructuredAuditLogger | None = None,
        event_factory: SecurityEventFactory | None = None,
    ) -> None:
        self._normalizer = normalizer or PromptNormalizer()
        self._rule_detector = rule_detector or PromptRuleDetector()
        self._encoding_detector = encoding_detector or EncodingDetector()
        self._obfuscation_detector = obfuscation_detector or ObfuscationDetector()
        self._jailbreak_detector = jailbreak_detector or JailbreakDetector()
        self._risk_engine = risk_engine or RiskEngine()
        self._policy_engine = policy_engine or PolicyEngine()
        self._audit_logger = audit_logger or StructuredAuditLogger()
        self._event_factory = event_factory or SecurityEventFactory()

    def scan(
        self,
        request: PromptScanRequest,
        *,
        trust_level: TrustLevel = TrustLevel.LIMITED,
    ) -> PromptScanResult:
        prompt_fingerprint = fingerprint(request.prompt)
        event = self._event_factory.create(
            event_type="prompt.scan",
            source="user",
            action="scan",
            target="input_security",
            resource_type="prompt",
            trust_level=trust_level,
            session_id=request.session_id,
            user_id=request.user_id,
            data={
                "prompt_fingerprint": prompt_fingerprint,
                "input_length": len(request.prompt),
            },
        )
        findings: tuple[PromptFinding, ...] = ()
        normalized_text = ""
        normalization_changed = False

        try:
            normalization = self._normalizer.normalize(request.prompt)
            normalized_text = normalization.normalized_text
            normalization_changed = normalization.changed
            findings = self._detect(request.prompt, normalization)
            security_findings = self._security_findings(findings)
            context = SecurityContext(
                user_trust=trust_level,
                agent_trust=TrustLevel.TRUSTED,
            )
            risk = self._risk_engine.score(event, context, security_findings)
            decision = self._policy_engine.decide(risk, security_findings)
            decision = decision.model_copy(update={
                "metadata": {
                    "finding_codes": [finding.code for finding in findings],
                    "normalization_changed": normalization_changed,
                },
            })
        except Exception as exc:
            failure = PromptFinding(
                code="PROMPT_SECURITY_ENGINE_FAILURE",
                category=PromptThreatCategory.INTERNAL_SECURITY_ERROR,
                severity=Severity.CRITICAL,
                risk_score=100,
                detector="prompt_firewall",
                evidence_fingerprint=fingerprint(type(exc).__name__),
                metadata={"error_type": type(exc).__name__},
            )
            findings = (failure,)
            decision = SecurityDecision(
                decision=DecisionAction.DENY,
                risk_score=100,
                reason_codes=(ReasonCode.UNKNOWN_SECURITY_STATE,),
                metadata={"finding_codes": [failure.code]},
            )

        self._audit_logger.record(event, decision)
        return PromptScanResult(
            event_id=event.event_id,
            decision=decision,
            findings=findings,
            prompt_fingerprint=prompt_fingerprint,
            normalized_fingerprint=fingerprint(normalized_text),
            normalization_changed=normalization_changed,
            input_length=len(request.prompt),
            normalized_length=len(normalized_text),
        )

    def _detect(
        self,
        raw_prompt: str,
        normalization: PromptNormalizationResult,
    ) -> tuple[PromptFinding, ...]:
        normalized_text = normalization.normalized_text
        findings: list[PromptFinding] = []
        findings.extend(self._rule_detector.detect(raw_prompt, normalized_text))
        findings.extend(self._encoding_detector.detect(raw_prompt, normalized_text))
        findings.extend(self._obfuscation_detector.detect(raw_prompt, normalization))
        findings.extend(self._jailbreak_detector.detect(raw_prompt, normalized_text))
        return tuple(sorted(findings, key=lambda item: (item.code, item.evidence_fingerprint)))

    @staticmethod
    def _security_findings(findings: Iterable[PromptFinding]) -> tuple[DetectionFinding, ...]:
        converted = [DetectionFinding(
            rule_id="ASEC-PROMPT-BASELINE",
            severity=Severity.INFO,
            risk_score=0,
            actions=(RuleAction.ALLOW, RuleAction.AUDIT),
        )]
        converted.extend(
            DetectionFinding(
                rule_id=f"ASEC-PROMPT-{finding.code}",
                severity=finding.severity,
                risk_score=finding.risk_score,
                actions=(RuleAction.AUDIT,),
                reason_codes=(finding.code,),
            )
            for finding in findings
        )
        return tuple(converted)
