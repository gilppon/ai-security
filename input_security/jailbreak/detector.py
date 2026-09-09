from detection.models import Severity
from input_security.jailbreak.patterns import JAILBREAK_PHRASES
from input_security.prompt.models import PromptFinding, PromptThreatCategory
from input_security.prompt.utils import fingerprint


class JailbreakDetector:
    name = "jailbreak_detector"

    def detect(self, raw_prompt: str, normalized_prompt: str) -> tuple[PromptFinding, ...]:
        comparable = normalized_prompt.casefold()
        matched = next((phrase for phrase in JAILBREAK_PHRASES if phrase in comparable), None)
        if matched is None:
            return ()
        return (PromptFinding(
            code="JAILBREAK_PATTERN",
            category=PromptThreatCategory.JAILBREAK,
            severity=Severity.CRITICAL,
            risk_score=70,
            detector=self.name,
            evidence_fingerprint=fingerprint(matched),
        ),)

