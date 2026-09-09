from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field, JsonValue

from core.decisions.actions import DecisionAction
from core.decisions.models import SecurityDecision
from core.events.types import TrustLevel
from detection.models import Severity


MAX_CONTENT_LENGTH = 262_144


class ContentType(StrEnum):
    PLAIN_TEXT = "plain_text"
    MARKDOWN = "markdown"
    HTML = "html"


class ContentSourceType(StrEnum):
    RAG_DOCUMENT = "rag_document"
    WEB = "web"
    EMAIL = "email"
    SLACK = "slack"
    NOTION = "notion"
    GITHUB = "github"
    TOOL_RESULT = "tool_result"
    UNKNOWN = "unknown"


class ContentThreatCategory(StrEnum):
    HIDDEN_CONTENT = "HIDDEN_CONTENT"
    ACTIVE_CONTENT = "ACTIVE_CONTENT"
    UNICODE_ABUSE = "UNICODE_ABUSE"
    INDIRECT_INSTRUCTION = "INDIRECT_INSTRUCTION"
    RAG_POISON = "RAG_POISON"
    SOURCE_TRUST = "SOURCE_TRUST"
    INVALID_CONTENT = "INVALID_CONTENT"
    INTERNAL_SECURITY_ERROR = "INTERNAL_SECURITY_ERROR"


class ContentFinding(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    code: str = Field(min_length=3, max_length=128, pattern=r"^[A-Z][A-Z0-9_]+$")
    category: ContentThreatCategory
    severity: Severity
    risk_score: int = Field(ge=0, le=100)
    detector: str = Field(min_length=1, max_length=128)
    evidence_fingerprint: str = Field(pattern=r"^[a-f0-9]{16}$")
    metadata: dict[str, JsonValue] = Field(default_factory=dict)


class ContentScanRequest(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", str_strip_whitespace=False)

    content: str = Field(min_length=1, max_length=MAX_CONTENT_LENGTH)
    content_type: ContentType
    source_type: ContentSourceType
    session_id: str | None = Field(default=None, max_length=128)


class SanitizedContentEnvelope(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    content: str
    security_event_id: str
    decision: DecisionAction
    content_fingerprint: str = Field(pattern=r"^[a-f0-9]{16}$")
    source_trust: TrustLevel


class ContentScanResult(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    event_id: str
    decision: SecurityDecision
    findings: tuple[ContentFinding, ...]
    source_trust: TrustLevel
    content_fingerprint: str = Field(pattern=r"^[a-f0-9]{16}$")
    sanitized_fingerprint: str = Field(pattern=r"^[a-f0-9]{16}$")
    sanitization_changed: bool
    input_length: int = Field(ge=0)
    sanitized_length: int = Field(ge=0)
    context: SanitizedContentEnvelope | None = None

