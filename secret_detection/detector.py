from dataclasses import dataclass
import re

from core.fingerprints import fingerprint_text
from detection.models import Severity
from secret_detection.context import is_placeholder
from secret_detection.entropy import shannon_entropy
from secret_detection.models import SecretCategory, SecretFinding, SecretLocation
from secret_detection.risk import secret_risk


@dataclass(frozen=True, slots=True)
class _Pattern:
    code: str
    category: SecretCategory
    expression: re.Pattern[str]
    value_group: str | None = None
    placeholder_aware: bool = False


_PATTERNS = (
    _Pattern(
        "SECRET_PRIVATE_KEY",
        SecretCategory.PRIVATE_KEY,
        re.compile(
            r"-----BEGIN [A-Z0-9 ]{0,32}PRIVATE KEY-----[\s\S]{16,16384}?"
            r"-----END [A-Z0-9 ]{0,32}PRIVATE KEY-----"
        ),
    ),
    _Pattern(
        "SECRET_GIT_TOKEN",
        SecretCategory.GIT_TOKEN,
        re.compile(
            r"(?<![A-Za-z0-9_])(?:gh[pousr]_[A-Za-z0-9]{30,255}|"
            r"github_pat_[A-Za-z0-9_]{20,255})(?![A-Za-z0-9_])"
        ),
    ),
    _Pattern(
        "SECRET_CLOUD_ACCESS_KEY",
        SecretCategory.CLOUD_ACCESS_KEY,
        re.compile(r"(?<![A-Z0-9])(?:AKIA|ASIA)[A-Z0-9]{16}(?![A-Z0-9])"),
    ),
    _Pattern(
        "SECRET_JWT",
        SecretCategory.JWT,
        re.compile(
            r"(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{5,1024}\."
            r"[A-Za-z0-9_-]{5,4096}\.[A-Za-z0-9_-]{5,1024}(?![A-Za-z0-9_-])"
        ),
    ),
    _Pattern(
        "SECRET_DATABASE_CREDENTIAL",
        SecretCategory.DATABASE_CREDENTIAL,
        re.compile(
            r"(?i)\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis)://"
            r"[^\s:/@]{1,128}:[^\s/@]{6,256}@[^\s]+"
        ),
    ),
    _Pattern(
        "SECRET_API_KEY",
        SecretCategory.API_KEY,
        re.compile(
            r"(?i)\b(?:api[_-]?key)\s*[:=]\s*['\"]?"
            r"(?P<value>[A-Za-z0-9_./+=-]{12,256})"
        ),
        value_group="value",
        placeholder_aware=True,
    ),
    _Pattern(
        "SECRET_GENERIC_CREDENTIAL",
        SecretCategory.GENERIC_CREDENTIAL,
        re.compile(
            r"(?i)\b(?:password|passwd|secret|access[_-]?token|auth[_-]?token)"
            r"\s*[:=]\s*['\"]?(?P<value>[^\s'\";,]{8,256})"
        ),
        value_group="value",
        placeholder_aware=True,
    ),
)


class SecretDetector:
    def detect(
        self,
        text: str,
        *,
        location: SecretLocation = SecretLocation.UNKNOWN,
    ) -> tuple[SecretFinding, ...]:
        findings: list[SecretFinding] = []
        occupied: list[tuple[int, int]] = []
        for pattern in _PATTERNS:
            for match in pattern.expression.finditer(text):
                start, end = (
                    match.span(pattern.value_group)
                    if pattern.value_group is not None
                    else match.span()
                )
                candidate = text[start:end]
                if pattern.placeholder_aware and is_placeholder(candidate):
                    continue
                if any(start < used_end and end > used_start for used_start, used_end in occupied):
                    continue
                entropy = shannon_entropy(candidate)
                risk = secret_risk(pattern.category, entropy, location)
                findings.append(SecretFinding(
                    code=pattern.code,
                    category=pattern.category,
                    severity=_severity(risk),
                    risk_score=risk,
                    detector="secret_detector",
                    evidence_fingerprint=fingerprint_text(candidate),
                    entropy=round(entropy, 4),
                    location=location,
                    start=start,
                    end=end,
                ))
                occupied.append((start, end))
        return tuple(sorted(findings, key=lambda item: (item.start, item.end, item.code)))


def _severity(risk: int) -> Severity:
    if risk >= 80:
        return Severity.CRITICAL
    if risk >= 61:
        return Severity.HIGH
    if risk >= 41:
        return Severity.MEDIUM
    return Severity.LOW
