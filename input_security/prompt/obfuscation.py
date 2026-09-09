import re
import unicodedata

from detection.models import Severity
from input_security.prompt.models import PromptFinding, PromptThreatCategory
from input_security.prompt.normalizer import PromptNormalizationResult
from input_security.prompt.utils import fingerprint


SEPARATOR_ABUSE = re.compile(r"(?i)(?:[a-z][._\-\s]){5,}[a-z]")
TOKEN = re.compile(r"[^\W\d_]+", re.UNICODE)


class ObfuscationDetector:
    name = "obfuscation_detector"

    def detect(
        self,
        raw_prompt: str,
        normalization: PromptNormalizationResult,
    ) -> tuple[PromptFinding, ...]:
        findings: list[PromptFinding] = []
        if normalization.removed_format_characters:
            findings.append(self._finding(
                code="UNICODE_FORMAT_CHARACTER",
                category=PromptThreatCategory.UNICODE_ABUSE,
                severity=Severity.MEDIUM,
                risk_score=30,
                evidence=raw_prompt,
                metadata={"count": normalization.removed_format_characters},
            ))
        if normalization.removed_control_characters:
            findings.append(self._finding(
                code="CONTROL_CHARACTER_ABUSE",
                category=PromptThreatCategory.OBFUSCATED_INSTRUCTION,
                severity=Severity.MEDIUM,
                risk_score=25,
                evidence=raw_prompt,
                metadata={"count": normalization.removed_control_characters},
            ))
        separator_match = SEPARATOR_ABUSE.search(normalization.normalized_text)
        if separator_match:
            findings.append(self._finding(
                code="SEPARATOR_OBFUSCATION",
                category=PromptThreatCategory.OBFUSCATED_INSTRUCTION,
                severity=Severity.HIGH,
                risk_score=45,
                evidence=separator_match.group(0),
            ))
        mixed_script = self._mixed_script_token(normalization.normalized_text)
        if mixed_script:
            findings.append(self._finding(
                code="MIXED_SCRIPT_OBFUSCATION",
                category=PromptThreatCategory.OBFUSCATED_INSTRUCTION,
                severity=Severity.HIGH,
                risk_score=40,
                evidence=mixed_script,
            ))
        if not normalization.normalized_text:
            findings.append(self._finding(
                code="EMPTY_AFTER_NORMALIZATION",
                category=PromptThreatCategory.INVALID_INPUT,
                severity=Severity.CRITICAL,
                risk_score=80,
                evidence=raw_prompt,
            ))
        return tuple(findings)

    @staticmethod
    def _mixed_script_token(text: str) -> str | None:
        for token in TOKEN.findall(text):
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

    def _finding(
        self,
        *,
        code: str,
        category: PromptThreatCategory,
        severity: Severity,
        risk_score: int,
        evidence: str,
        metadata: dict[str, int] | None = None,
    ) -> PromptFinding:
        return PromptFinding(
            code=code,
            category=category,
            severity=severity,
            risk_score=risk_score,
            detector=self.name,
            evidence_fingerprint=fingerprint(evidence),
            metadata=metadata or {},
        )

