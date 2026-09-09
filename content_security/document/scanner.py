from dataclasses import dataclass

from content_security.document.hidden_text import HiddenContentDetector
from content_security.document.instruction import InstructionDetector
from content_security.document.normalizer import ContentNormalizer
from content_security.document.sanitizer import ContentSanitizer
from content_security.document.unicode import UnicodeContentDetector
from content_security.models import ContentFinding, ContentThreatCategory, ContentType
from content_security.utils import fingerprint
from detection.models import Severity


@dataclass(frozen=True, slots=True)
class DocumentScan:
    normalized_content: str
    sanitized_content: str
    findings: tuple[ContentFinding, ...]


class DocumentScanner:
    def __init__(
        self,
        *,
        normalizer: ContentNormalizer | None = None,
        hidden_detector: HiddenContentDetector | None = None,
        unicode_detector: UnicodeContentDetector | None = None,
        instruction_detector: InstructionDetector | None = None,
        sanitizer: ContentSanitizer | None = None,
    ) -> None:
        self._normalizer = normalizer or ContentNormalizer()
        self._hidden_detector = hidden_detector or HiddenContentDetector()
        self._unicode_detector = unicode_detector or UnicodeContentDetector()
        self._instruction_detector = instruction_detector or InstructionDetector()
        self._sanitizer = sanitizer or ContentSanitizer(self._normalizer)

    def scan(self, content: str, content_type: ContentType) -> DocumentScan:
        normalization = self._normalizer.normalize(content)
        findings: tuple[ContentFinding, ...] = (
            *self._hidden_detector.detect(content, content_type),
            *self._unicode_detector.detect(content, normalization),
            *self._instruction_detector.detect(normalization.normalized_text),
        )
        sanitized = self._sanitizer.sanitize(content, content_type)
        if not sanitized:
            findings = (*findings, ContentFinding(
                code="EMPTY_SANITIZED_CONTENT",
                category=ContentThreatCategory.INVALID_CONTENT,
                severity=Severity.CRITICAL,
                risk_score=80,
                detector="document_scanner",
                evidence_fingerprint=fingerprint(content),
            ))
        return DocumentScan(
            normalized_content=normalization.normalized_text,
            sanitized_content=sanitized,
            findings=tuple(sorted(findings, key=lambda item: (item.code, item.evidence_fingerprint))),
        )
