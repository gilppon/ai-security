from typing import Protocol

from input_security.prompt.models import PromptFinding
from input_security.prompt.normalizer import PromptNormalizationResult


class PromptNormalizerContract(Protocol):
    def normalize(self, prompt: str) -> PromptNormalizationResult: ...


class PromptTextDetectorContract(Protocol):
    def detect(self, raw_prompt: str, normalized_prompt: str) -> tuple[PromptFinding, ...]: ...


class PromptObfuscationDetectorContract(Protocol):
    def detect(
        self,
        raw_prompt: str,
        normalization: PromptNormalizationResult,
    ) -> tuple[PromptFinding, ...]: ...

