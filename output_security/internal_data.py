import re

from core.fingerprints import fingerprint_text
from detection.models import Severity
from output_security.models import OutputThreatCategory, SensitiveSpan


_INTERNAL_MARKERS = re.compile(
    r"(?i)(?:<\|system\|>|BEGIN[ _-]+SYSTEM[ _-]+PROMPT|INTERNAL[ _-]+SECURITY[ _-]+POLICY)"
)


class InternalDataDetector:
    def detect(self, text: str) -> tuple[SensitiveSpan, ...]:
        return tuple(SensitiveSpan(
            code="OUTPUT_INTERNAL_DATA",
            category=OutputThreatCategory.INTERNAL_DATA,
            severity=Severity.CRITICAL,
            risk_score=100,
            detector="internal_data_detector",
            evidence_fingerprint=fingerprint_text(match.group()),
            start=match.start(),
            end=match.end(),
            replacement_label="INTERNAL_DATA",
        ) for match in _INTERNAL_MARKERS.finditer(text))
