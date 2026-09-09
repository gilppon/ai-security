import unicodedata
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class PromptNormalizationResult:
    normalized_text: str
    changed: bool
    removed_format_characters: int
    removed_control_characters: int


class PromptNormalizer:
    def normalize(self, prompt: str) -> PromptNormalizationResult:
        canonical = unicodedata.normalize("NFKC", prompt.replace("\r\n", "\n").replace("\r", "\n"))
        output: list[str] = []
        removed_format = 0
        removed_control = 0

        for character in canonical:
            category = unicodedata.category(character)
            if category == "Cf":
                removed_format += 1
                continue
            if category == "Cc" and character not in {"\n", "\t"}:
                removed_control += 1
                continue
            output.append(character)

        normalized = "".join(output).strip()
        return PromptNormalizationResult(
            normalized_text=normalized,
            changed=normalized != prompt,
            removed_format_characters=removed_format,
            removed_control_characters=removed_control,
        )

