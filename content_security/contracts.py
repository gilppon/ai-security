from typing import Protocol

from core.decisions.actions import DecisionAction
from core.events.types import TrustLevel
from content_security.document.scanner import DocumentScan
from content_security.models import ContentSourceType, ContentType, SanitizedContentEnvelope
from content_security.source_trust.models import SourceTrustAssessment


class DocumentScannerContract(Protocol):
    def scan(self, content: str, content_type: ContentType) -> DocumentScan: ...


class SourceTrustEngineContract(Protocol):
    def assess(
        self,
        source_type: ContentSourceType,
        *,
        verified_trust: TrustLevel | None = None,
    ) -> SourceTrustAssessment: ...


class ContextIsolationContract(Protocol):
    def release(
        self,
        *,
        sanitized_content: str,
        event_id: str,
        decision: DecisionAction,
        source_trust: TrustLevel,
    ) -> SanitizedContentEnvelope | None: ...

