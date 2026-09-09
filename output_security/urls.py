import re
from urllib.parse import parse_qsl, urlsplit

from core.fingerprints import fingerprint_text
from detection.models import Severity
from output_security.models import OutputThreatCategory, SensitiveSpan


_URL = re.compile(r"https?://[^\s<>\"']{1,8192}", re.IGNORECASE)
_SENSITIVE_QUERY_NAMES = {"access_token", "api_key", "apikey", "auth", "key", "password", "secret", "token"}


class SensitiveURLDetector:
    def detect(self, text: str) -> tuple[SensitiveSpan, ...]:
        findings: list[SensitiveSpan] = []
        for match in _URL.finditer(text):
            candidate = match.group().rstrip(".,);]")
            parsed = urlsplit(candidate)
            query_names = {name.casefold() for name, _ in parse_qsl(parsed.query, keep_blank_values=True)}
            if parsed.username is None and parsed.password is None and not query_names.intersection(_SENSITIVE_QUERY_NAMES):
                continue
            findings.append(SensitiveSpan(
                code="OUTPUT_SENSITIVE_URL",
                category=OutputThreatCategory.SENSITIVE_URL,
                severity=Severity.CRITICAL,
                risk_score=90,
                detector="sensitive_url_detector",
                evidence_fingerprint=fingerprint_text(candidate),
                start=match.start(),
                end=match.start() + len(candidate),
                replacement_label="SENSITIVE_URL",
            ))
        return tuple(findings)
