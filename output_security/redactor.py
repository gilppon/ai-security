from output_security.models import SensitiveSpan


_ALLOWED_LABELS = {
    "EMAIL",
    "PHONE",
    "PAYMENT_CARD",
    "SENSITIVE_URL",
    "INTERNAL_DATA",
    "SECRET_API_KEY",
    "SECRET_GIT_TOKEN",
    "SECRET_CLOUD_ACCESS_KEY",
    "SECRET_JWT",
    "SECRET_PRIVATE_KEY",
    "SECRET_DATABASE_CREDENTIAL",
    "SECRET_GENERIC_CREDENTIAL",
}


class OutputRedactor:
    def redact(self, text: str, spans: tuple[SensitiveSpan, ...]) -> tuple[str, int]:
        merged = _merge_spans(spans)
        if not merged:
            return text, 0
        parts: list[str] = []
        cursor = 0
        for start, end, labels in merged:
            parts.append(text[cursor:start])
            label = (
                labels[0]
                if len(labels) == 1 and labels[0] in _ALLOWED_LABELS
                else "SENSITIVE_DATA"
            )
            parts.append(f"[REDACTED:{label}]")
            cursor = end
        parts.append(text[cursor:])
        return "".join(parts), len(merged)


def _merge_spans(spans: tuple[SensitiveSpan, ...]) -> list[tuple[int, int, tuple[str, ...]]]:
    valid = sorted(
        (span for span in spans if 0 <= span.start < span.end),
        key=lambda item: (item.start, item.end, item.replacement_label),
    )
    merged: list[tuple[int, int, set[str]]] = []
    for span in valid:
        if not merged or span.start > merged[-1][1]:
            merged.append((span.start, span.end, {span.replacement_label}))
            continue
        start, end, labels = merged[-1]
        labels.add(span.replacement_label)
        merged[-1] = (start, max(end, span.end), labels)
    return [(start, end, tuple(sorted(labels))) for start, end, labels in merged]
