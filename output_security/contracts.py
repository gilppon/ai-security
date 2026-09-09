from typing import Protocol

from output_security.models import SensitiveSpan
from secret_detection.models import SecretFinding, SecretLocation


class SecretDetectorContract(Protocol):
    def detect(
        self,
        text: str,
        *,
        location: SecretLocation = SecretLocation.UNKNOWN,
    ) -> tuple[SecretFinding, ...]: ...


class OutputSpanDetectorContract(Protocol):
    def detect(self, text: str) -> tuple[SensitiveSpan, ...]: ...


class OutputRedactorContract(Protocol):
    def redact(self, text: str, spans: tuple[SensitiveSpan, ...]) -> tuple[str, int]: ...
