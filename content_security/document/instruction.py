from dataclasses import dataclass

from content_security.models import ContentFinding, ContentThreatCategory
from content_security.utils import fingerprint
from detection.models import Severity


@dataclass(frozen=True, slots=True)
class InstructionRule:
    code: str
    category: ContentThreatCategory
    severity: Severity
    risk_score: int
    phrases: tuple[str, ...]


RULES = (
    InstructionRule(
        code="EXTERNAL_INSTRUCTION_OVERRIDE",
        category=ContentThreatCategory.INDIRECT_INSTRUCTION,
        severity=Severity.CRITICAL,
        risk_score=65,
        phrases=("ignore previous instructions", "follow these instructions instead", "when read by an ai"),
    ),
    InstructionRule(
        code="EXTERNAL_SYSTEM_TAG",
        category=ContentThreatCategory.RAG_POISON,
        severity=Severity.HIGH,
        risk_score=60,
        phrases=("<system>", "system message:", "assistant instructions:"),
    ),
    InstructionRule(
        code="EXTERNAL_TOOL_DIRECTIVE",
        category=ContentThreatCategory.RAG_POISON,
        severity=Severity.CRITICAL,
        risk_score=65,
        phrases=("call the tool", "invoke the tool", "tool arguments:"),
    ),
    InstructionRule(
        code="EXTERNAL_EXFILTRATION_DIRECTIVE",
        category=ContentThreatCategory.RAG_POISON,
        severity=Severity.CRITICAL,
        risk_score=75,
        phrases=("retrieve secrets", "send environment variables", "upload credentials"),
    ),
)


class InstructionDetector:
    name = "instruction_detector"

    def detect(self, content: str) -> tuple[ContentFinding, ...]:
        comparable = content.casefold()
        findings: list[ContentFinding] = []
        for rule in RULES:
            matched = next((phrase for phrase in rule.phrases if phrase in comparable), None)
            if matched:
                findings.append(ContentFinding(
                    code=rule.code,
                    category=rule.category,
                    severity=rule.severity,
                    risk_score=rule.risk_score,
                    detector=self.name,
                    evidence_fingerprint=fingerprint(matched),
                ))
        return tuple(findings)

