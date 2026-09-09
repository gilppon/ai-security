import re

from core.fingerprints import fingerprint_text
from detection.models import Severity
from output_security.models import OutputThreatCategory, SensitiveSpan


_EMAIL = re.compile(r"(?<![\w.+-])[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]{1,64}@[A-Za-z0-9-]{1,63}(?:\.[A-Za-z0-9-]{1,63})+(?![\w.-])")
_PHONE = re.compile(r"(?<!\w)(?:\+?\d[\d .()-]{6,24}\d)(?!\w)")
_CARD = re.compile(r"(?<!\d)(?:\d[ -]?){12,18}\d(?!\d)")


class PIIDetector:
    def detect(self, text: str) -> tuple[SensitiveSpan, ...]:
        spans: list[SensitiveSpan] = []
        spans.extend(self._matches(text, _EMAIL, "PII_EMAIL", "EMAIL", 20, Severity.LOW))
        for match in _CARD.finditer(text):
            digits = "".join(character for character in match.group() if character.isdigit())
            if 13 <= len(digits) <= 19 and _luhn_valid(digits):
                spans.append(_span(match, "PII_PAYMENT_CARD", "PAYMENT_CARD", 55, Severity.MEDIUM))
        for match in _PHONE.finditer(text):
            digits = "".join(character for character in match.group() if character.isdigit())
            if 8 <= len(digits) <= 15:
                spans.append(_span(match, "PII_PHONE", "PHONE", 30, Severity.MEDIUM))
        return tuple(sorted(spans, key=lambda item: (item.start, item.end, item.code)))

    @staticmethod
    def _matches(
        text: str,
        expression: re.Pattern[str],
        code: str,
        label: str,
        risk: int,
        severity: Severity,
    ) -> list[SensitiveSpan]:
        return [_span(match, code, label, risk, severity) for match in expression.finditer(text)]


def _span(
    match: re.Match[str],
    code: str,
    label: str,
    risk: int,
    severity: Severity,
) -> SensitiveSpan:
    return SensitiveSpan(
        code=code,
        category=OutputThreatCategory.PII,
        severity=severity,
        risk_score=risk,
        detector="pii_detector",
        evidence_fingerprint=fingerprint_text(match.group()),
        start=match.start(),
        end=match.end(),
        replacement_label=label,
    )


def _luhn_valid(digits: str) -> bool:
    total = 0
    parity = len(digits) % 2
    for index, character in enumerate(digits):
        value = int(character)
        if index % 2 == parity:
            value *= 2
            if value > 9:
                value -= 9
        total += value
    return total % 10 == 0
