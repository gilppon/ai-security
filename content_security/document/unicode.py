import re
import unicodedata

from content_security.document.normalizer import ContentNormalizationResult
from content_security.models import ContentFinding, ContentThreatCategory
from content_security.utils import fingerprint
from detection.models import Severity


TOKEN = re.compile(r"[^\W\d_]+", re.UNICODE)


class UnicodeContentDetector:
    name = "unicode_content_detector"

    def detect(
        self,
        content: str,
        normalization: ContentNormalizationResult,
    ) -> tuple[ContentFinding, ...]:
        findings: list[ContentFinding] = []
        controls = (
            normalization.removed_format_characters
            + normalization.removed_bidi_controls
            + normalization.removed_control_characters
        )
        if controls:
            findings.append(ContentFinding(
                code="UNICODE_CONTROL_CONTENT",
                category=ContentThreatCategory.UNICODE_ABUSE,
                severity=Severity.MEDIUM,
                risk_score=30,
                detector=self.name,
                evidence_fingerprint=fingerprint(content),
                metadata={
                    "format_count": normalization.removed_format_characters,
                    "bidi_count": normalization.removed_bidi_controls,
                    "control_count": normalization.removed_control_characters,
                },
            ))
        mixed = self._mixed_script_token(normalization.normalized_text)
        if mixed:
            findings.append(ContentFinding(
                code="MIXED_SCRIPT_CONTENT",
                category=ContentThreatCategory.UNICODE_ABUSE,
                severity=Severity.HIGH,
                risk_score=40,
                detector=self.name,
                evidence_fingerprint=fingerprint(mixed),
            ))
        return tuple(findings)

    @staticmethod
    def _mixed_script_token(content: str) -> str | None:
        for token in TOKEN.findall(content):
            scripts = set()
            for character in token:
                name = unicodedata.name(character, "")
                if "LATIN" in name:
                    scripts.add("LATIN")
                elif "CYRILLIC" in name:
                    scripts.add("CYRILLIC")
            if len(scripts) > 1:
                return token
        return None

