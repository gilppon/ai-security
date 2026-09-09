from output_security.models import OutputThreatCategory, SensitiveSpan
from secret_detection.models import SecretFinding


def secret_spans(findings: tuple[SecretFinding, ...]) -> tuple[SensitiveSpan, ...]:
    return tuple(SensitiveSpan(
        code=finding.code,
        category=OutputThreatCategory.SECRET,
        severity=finding.severity,
        risk_score=finding.risk_score,
        detector=finding.detector,
        evidence_fingerprint=finding.evidence_fingerprint,
        start=finding.start,
        end=finding.end,
        replacement_label=f"SECRET_{finding.category.value}",
        metadata={
            "secret_category": finding.category.value,
            "location": finding.location.value,
        },
    ) for finding in findings)
