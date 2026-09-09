from detection.models import Severity
from pydantic import JsonValue
from content_security.document.html import HTMLInspectionParser
from content_security.models import ContentFinding, ContentThreatCategory, ContentType
from content_security.utils import fingerprint


INSTRUCTION_MARKERS = (
    "ignore previous instructions",
    "follow these instructions",
    "system prompt",
    "call the tool",
    "retrieve secrets",
)


class HiddenContentDetector:
    name = "hidden_content_detector"

    def detect(self, content: str, content_type: ContentType) -> tuple[ContentFinding, ...]:
        if content_type is ContentType.PLAIN_TEXT:
            return ()
        parser = HTMLInspectionParser()
        parser.feed(content)
        parser.close()
        findings: list[ContentFinding] = []
        hidden_parts = parser.comments + parser.hidden_text
        hidden_text = "\n".join(hidden_parts)
        if hidden_parts:
            findings.append(self._finding(
                code="HIDDEN_CONTENT_PRESENT",
                category=ContentThreatCategory.HIDDEN_CONTENT,
                severity=Severity.LOW,
                risk_score=15,
                evidence=hidden_text,
                metadata={"segments": len(hidden_parts)},
            ))
        if hidden_text and any(marker in hidden_text.casefold() for marker in INSTRUCTION_MARKERS):
            findings.append(self._finding(
                code="HIDDEN_INSTRUCTION",
                category=ContentThreatCategory.INDIRECT_INSTRUCTION,
                severity=Severity.CRITICAL,
                risk_score=65,
                evidence=hidden_text,
            ))
        if parser.active_tags:
            findings.append(self._finding(
                code="ACTIVE_HTML_CONTENT",
                category=ContentThreatCategory.ACTIVE_CONTENT,
                severity=Severity.CRITICAL,
                risk_score=60,
                evidence="|".join(parser.active_tags),
                metadata={"tags": sorted(set(parser.active_tags))},
            ))
        return tuple(findings)

    def _finding(
        self,
        *,
        code: str,
        category: ContentThreatCategory,
        severity: Severity,
        risk_score: int,
        evidence: str,
        metadata: dict[str, JsonValue] | None = None,
    ) -> ContentFinding:
        return ContentFinding(
            code=code,
            category=category,
            severity=severity,
            risk_score=risk_score,
            detector=self.name,
            evidence_fingerprint=fingerprint(evidence),
            metadata=metadata or {},
        )
