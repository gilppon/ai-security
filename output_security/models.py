from dataclasses import dataclass
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field, JsonValue

from core.decisions.models import SecurityDecision
from detection.models import Severity


MAX_OUTPUT_LENGTH = 262_144


class OutputThreatCategory(StrEnum):
    SECRET = "SECRET"
    PII = "PII"
    SENSITIVE_URL = "SENSITIVE_URL"
    INTERNAL_DATA = "INTERNAL_DATA"
    INTERNAL_SECURITY_ERROR = "INTERNAL_SECURITY_ERROR"


class OutputSource(StrEnum):
    LLM = "llm"
    MCP_RESULT = "mcp_result"


@dataclass(frozen=True, slots=True)
class SensitiveSpan:
    code: str
    category: OutputThreatCategory
    severity: Severity
    risk_score: int
    detector: str
    evidence_fingerprint: str
    start: int
    end: int
    replacement_label: str
    metadata: dict[str, JsonValue] | None = None


class OutputFinding(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    code: str = Field(pattern=r"^[A-Z][A-Z0-9_]+$")
    category: OutputThreatCategory
    severity: Severity
    risk_score: int = Field(ge=0, le=100)
    detector: str = Field(min_length=1, max_length=64)
    evidence_fingerprint: str = Field(pattern=r"^[a-f0-9]{16}$")
    metadata: dict[str, JsonValue] = Field(default_factory=dict)


class OutputScanRequest(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", str_strip_whitespace=False)

    output: str = Field(min_length=1, max_length=MAX_OUTPUT_LENGTH)
    session_id: str | None = Field(default=None, max_length=128)
    user_id: str | None = Field(default=None, max_length=128)


class OutputScanResult(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    event_id: str
    decision: SecurityDecision
    findings: tuple[OutputFinding, ...]
    output_fingerprint: str = Field(pattern=r"^[a-f0-9]{16}$")
    released_fingerprint: str | None = Field(default=None, pattern=r"^[a-f0-9]{16}$")
    output_length: int = Field(ge=0)
    released_length: int = Field(ge=0)
    redaction_count: int = Field(ge=0)
    released_output: str | None = None
