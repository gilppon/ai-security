import base64
import binascii
import re
from itertools import islice

from detection.models import Severity
from input_security.prompt.models import PromptFinding, PromptThreatCategory
from input_security.prompt.utils import fingerprint


BASE64_TOKEN = re.compile(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{24,8192}={0,2}(?![A-Za-z0-9+/=])")
HEX_TOKEN = re.compile(r"(?<![0-9A-Fa-f])[0-9A-Fa-f]{32,8192}(?![0-9A-Fa-f])")
SUSPICIOUS_DECODED_PHRASES = (
    "ignore previous instructions",
    "system prompt",
    "call the tool",
    "send the secret",
    "bypass safety",
)
MAX_CANDIDATES = 16


class EncodingDetector:
    name = "encoding_detector"

    def detect(self, raw_prompt: str, normalized_prompt: str) -> tuple[PromptFinding, ...]:
        findings: list[PromptFinding] = []
        seen: set[str] = set()

        for match in islice(BASE64_TOKEN.finditer(normalized_prompt), MAX_CANDIDATES):
            decoded = self._decode_base64(match.group(0))
            finding = self._finding(decoded, "base64", match.group(0))
            if finding and finding.evidence_fingerprint not in seen:
                findings.append(finding)
                seen.add(finding.evidence_fingerprint)

        for match in islice(HEX_TOKEN.finditer(normalized_prompt), MAX_CANDIDATES):
            decoded = self._decode_hex(match.group(0))
            finding = self._finding(decoded, "hex", match.group(0))
            if finding and finding.evidence_fingerprint not in seen:
                findings.append(finding)
                seen.add(finding.evidence_fingerprint)

        return tuple(findings)

    @staticmethod
    def _decode_base64(candidate: str) -> str | None:
        try:
            padded = candidate + ("=" * (-len(candidate) % 4))
            decoded = base64.b64decode(padded, validate=True)
            return decoded.decode("utf-8")
        except (binascii.Error, UnicodeDecodeError, ValueError):
            return None

    @staticmethod
    def _decode_hex(candidate: str) -> str | None:
        if len(candidate) % 2:
            return None
        try:
            return bytes.fromhex(candidate).decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            return None

    def _finding(self, decoded: str | None, encoding: str, encoded: str) -> PromptFinding | None:
        if decoded is None or not decoded:
            return None
        printable_ratio = sum(character.isprintable() or character.isspace() for character in decoded) / len(decoded)
        if printable_ratio < 0.85:
            return None
        comparable = decoded.casefold()
        if not any(phrase in comparable for phrase in SUSPICIOUS_DECODED_PHRASES):
            return None
        return PromptFinding(
            code="ENCODED_SUSPICIOUS_INSTRUCTION",
            category=PromptThreatCategory.ENCODED_INSTRUCTION,
            severity=Severity.HIGH,
            risk_score=55,
            detector=self.name,
            evidence_fingerprint=fingerprint(encoded),
            metadata={"encoding": encoding},
        )
