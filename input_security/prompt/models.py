from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field, JsonValue

from core.decisions.models import SecurityDecision
from detection.models import Severity


MAX_PROMPT_LENGTH = 65_536


class PromptThreatCategory(StrEnum):
    SYSTEM_OVERRIDE = "SYSTEM_OVERRIDE"
    SYSTEM_PROMPT_EXTRACTION = "SYSTEM_PROMPT_EXTRACTION"
    ROLE_OVERRIDE = "ROLE_OVERRIDE"
    JAILBREAK = "JAILBREAK"
    ENCODED_INSTRUCTION = "ENCODED_INSTRUCTION"
    OBFUSCATED_INSTRUCTION = "OBFUSCATED_INSTRUCTION"
    TOOL_MANIPULATION = "TOOL_MANIPULATION"
    DATA_EXFILTRATION = "DATA_EXFILTRATION"
    UNICODE_ABUSE = "UNICODE_ABUSE"
    INVALID_INPUT = "INVALID_INPUT"
    INTERNAL_SECURITY_ERROR = "INTERNAL_SECURITY_ERROR"


class PromptFinding(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    code: str = Field(min_length=3, max_length=128, pattern=r"^[A-Z][A-Z0-9_]+$")
    category: PromptThreatCategory
    severity: Severity
    risk_score: int = Field(ge=0, le=100)
    detector: str = Field(min_length=1, max_length=128)
    evidence_fingerprint: str = Field(pattern=r"^[a-f0-9]{16}$")
    metadata: dict[str, JsonValue] = Field(default_factory=dict)


class PromptScanRequest(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", str_strip_whitespace=False)

    prompt: str = Field(min_length=1, max_length=MAX_PROMPT_LENGTH)
    session_id: str | None = Field(default=None, max_length=128)
    user_id: str | None = Field(default=None, max_length=128)


class PromptScanResult(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    event_id: str
    decision: SecurityDecision
    findings: tuple[PromptFinding, ...]
    prompt_fingerprint: str = Field(pattern=r"^[a-f0-9]{16}$")
    normalized_fingerprint: str = Field(pattern=r"^[a-f0-9]{16}$")
    normalization_changed: bool
    input_length: int = Field(ge=0)
    normalized_length: int = Field(ge=0)

