from core.decisions.actions import DecisionAction
from core.decisions.reasons import ReasonCode
from detection.models import Severity
from output_security.guard import OutputGuard
from output_security.models import (
    OutputScanRequest,
    OutputThreatCategory,
    SensitiveSpan,
)
from output_security.redactor import OutputRedactor
from telemetry.audit import InMemoryAuditSink, StructuredAuditLogger


class FailingDetector:
    def detect(self, text: str):
        raise RuntimeError("detector unavailable")


class InvalidSpanDetector:
    def detect(self, text: str):
        return (SensitiveSpan(
            code="PII_INVALID",
            category=OutputThreatCategory.PII,
            severity=Severity.MEDIUM,
            risk_score=20,
            detector="test",
            evidence_fingerprint="c" * 16,
            start=0,
            end=len(text) + 1,
            replacement_label="PHONE",
        ),)


class MetadataLeakDetector:
    def detect(self, text: str):
        return (SensitiveSpan(
            code="PII_CUSTOM",
            category=OutputThreatCategory.PII,
            severity=Severity.MEDIUM,
            risk_score=20,
            detector="test",
            evidence_fingerprint="d" * 16,
            start=0,
            end=len(text),
            replacement_label="PRIVATE_VALUE",
            metadata={"raw_secret": "PRIVATE_VALUE", "location": "PRIVATE_VALUE"},
        ),)


def test_clean_output_is_released_and_audited_without_raw_content() -> None:
    raw = "The operation completed successfully."
    sink = InMemoryAuditSink()
    guard = OutputGuard(audit_logger=StructuredAuditLogger(sink))

    result = guard.scan(OutputScanRequest(output=raw))

    assert result.decision.decision is DecisionAction.ALLOW
    assert ReasonCode.OUTPUT_AUTHORIZED in result.decision.reason_codes
    assert result.released_output == raw
    assert raw not in "".join(sink.records)


def test_email_and_phone_are_redacted_before_release() -> None:
    raw = "Contact jane@example.com or +1 (212) 555-0198."

    result = OutputGuard().scan(OutputScanRequest(output=raw))

    assert result.decision.decision is DecisionAction.SANITIZE
    assert ReasonCode.PII_DETECTED in result.decision.reason_codes
    assert result.released_output is not None
    assert "jane@example.com" not in result.released_output
    assert "555-0198" not in result.released_output
    assert result.redaction_count == 2


def test_secret_in_production_output_is_denied_without_release_or_raw_audit() -> None:
    raw_secret = "api_key=AbCDef0123456789xyzXYZ"
    sink = InMemoryAuditSink()
    guard = OutputGuard(audit_logger=StructuredAuditLogger(sink))

    result = guard.scan(OutputScanRequest(output=f"Credential: {raw_secret}"))

    assert result.decision.decision is DecisionAction.DENY
    assert ReasonCode.SECRET_DETECTED in result.decision.reason_codes
    assert ReasonCode.OUTPUT_AUTHORIZED not in result.decision.reason_codes
    assert ReasonCode.OUTPUT_SANITIZED not in result.decision.reason_codes
    assert result.released_output is None
    assert raw_secret not in result.model_dump_json()
    assert raw_secret not in "".join(sink.records)


def test_sensitive_url_and_internal_policy_text_are_denied() -> None:
    sensitive_url = OutputGuard().scan(OutputScanRequest(
        output="Use https://api.example.com/data?access_token=private-value",
    ))
    internal = OutputGuard().scan(OutputScanRequest(
        output="BEGIN SYSTEM PROMPT: confidential instructions",
    ))

    assert ReasonCode.SENSITIVE_URL_DETECTED in sensitive_url.decision.reason_codes
    assert sensitive_url.released_output is None
    assert ReasonCode.INTERNAL_DATA_DETECTED in internal.decision.reason_codes
    assert internal.released_output is None


def test_valid_payment_card_is_classified_and_not_released() -> None:
    result = OutputGuard().scan(OutputScanRequest(
        output="Payment card: 4111 1111 1111 1111",
    ))

    assert any(finding.code == "PII_PAYMENT_CARD" for finding in result.findings)
    assert ReasonCode.PII_DETECTED in result.decision.reason_codes
    assert result.released_output is None


def test_detector_failure_defaults_to_deny() -> None:
    result = OutputGuard(pii_detector=FailingDetector()).scan(OutputScanRequest(output="safe text"))

    assert result.decision.decision is DecisionAction.DENY
    assert result.decision.reason_codes == (ReasonCode.OUTPUT_SECURITY_FAILURE,)
    assert result.released_output is None


def test_invalid_detector_span_defaults_to_deny() -> None:
    result = OutputGuard(pii_detector=InvalidSpanDetector()).scan(
        OutputScanRequest(output="safe text")
    )

    assert result.decision.decision is DecisionAction.DENY
    assert result.decision.reason_codes == (ReasonCode.OUTPUT_SECURITY_FAILURE,)
    assert result.released_output is None


def test_detector_metadata_and_labels_cannot_echo_sensitive_values() -> None:
    result = OutputGuard(pii_detector=MetadataLeakDetector()).scan(
        OutputScanRequest(output="sensitive")
    )

    assert result.decision.decision is DecisionAction.SANITIZE
    assert result.released_output == "[REDACTED:SENSITIVE_DATA]"
    assert "PRIVATE_VALUE" not in result.model_dump_json()


def test_redactor_merges_overlapping_spans_without_leaking_tail() -> None:
    spans = (
        SensitiveSpan(
            code="PII_PHONE",
            category=OutputThreatCategory.PII,
            severity=Severity.MEDIUM,
            risk_score=30,
            detector="test",
            evidence_fingerprint="a" * 16,
            start=2,
            end=8,
            replacement_label="PHONE",
        ),
        SensitiveSpan(
            code="PII_PAYMENT_CARD",
            category=OutputThreatCategory.PII,
            severity=Severity.MEDIUM,
            risk_score=55,
            detector="test",
            evidence_fingerprint="b" * 16,
            start=5,
            end=11,
            replacement_label="PAYMENT_CARD",
        ),
    )

    redacted, count = OutputRedactor().redact("00SECRETEND", spans)

    assert redacted == "00[REDACTED:SENSITIVE_DATA]"
    assert count == 1
