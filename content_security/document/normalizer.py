import unicodedata
from dataclasses import dataclass


BIDI_CONTROLS = frozenset({
    "\u061c", "\u200e", "\u200f", "\u202a", "\u202b", "\u202c", "\u202d", "\u202e",
    "\u2066", "\u2067", "\u2068", "\u2069",
})


@dataclass(frozen=True, slots=True)
class ContentNormalizationResult:
    normalized_text: str
    changed: bool
    removed_format_characters: int
    removed_bidi_controls: int
    removed_control_characters: int


class ContentNormalizer:
    def normalize(self, content: str) -> ContentNormalizationResult:
        canonical = unicodedata.normalize("NFKC", content.replace("\r\n", "\n").replace("\r", "\n"))
        output: list[str] = []
        removed_format = 0
        removed_bidi = 0
        removed_control = 0
        for character in canonical:
            category = unicodedata.category(character)
            if character in BIDI_CONTROLS:
                removed_bidi += 1
                continue
            if category == "Cf":
                removed_format += 1
                continue
            if category == "Cc" and character not in {"\n", "\t"}:
                removed_control += 1
                continue
            output.append(character)
        normalized = "".join(output).strip()
        return ContentNormalizationResult(
            normalized_text=normalized,
            changed=normalized != content,
            removed_format_characters=removed_format,
            removed_bidi_controls=removed_bidi,
            removed_control_characters=removed_control,
        )

