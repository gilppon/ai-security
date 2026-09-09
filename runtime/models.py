from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field

from core.decisions.models import SecurityDecision
from detection.models import Severity


class RuntimeActivity(StrEnum):
    PROMPT = "prompt"
    TOOL_SELECTION = "tool_selection"
    TOOL_CALL = "tool_call"
    FILE_ACCESS = "file_access"
    NETWORK_REQUEST = "network_request"
    PROCESS_START = "process_start"
    MCP_CALL = "mcp_call"
    OUTPUT = "output"


class RuntimeOutcome(StrEnum):
    ALLOWED = "allowed"
    BLOCKED = "blocked"
    FAILED = "failed"


class RuntimeEventRequest(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    session_id: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9_.:-]+$")
    activity: RuntimeActivity
    outcome: RuntimeOutcome
    target_fingerprint: str | None = Field(default=None, pattern=r"^[a-f0-9]{16}$")
    source_event_id: str | None = Field(
        default=None,
        max_length=128,
        pattern=r"^[A-Za-z0-9_.:-]+$",
    )


@dataclass(frozen=True, slots=True)
class RuntimeObservation:
    runtime_event_id: str
    source_event_id: str | None
    timestamp: datetime
    session_id: str
    agent_id: str
    activity: RuntimeActivity
    outcome: RuntimeOutcome
    target_fingerprint: str | None
    reason_codes: tuple[str, ...] = ()


class RuntimeFinding(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    code: str = Field(pattern=r"^RUNTIME_[A-Z_]+$")
    severity: Severity
    risk_score: int = Field(ge=0, le=100)
    reason_code: str = Field(pattern=r"^RUNTIME_[A-Z_]+$")


class RuntimeObservationResult(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    event_id: str
    decision: SecurityDecision
    findings: tuple[RuntimeFinding, ...]
    session_event_count: int = Field(default=0, ge=0)


class SessionSummary(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    session_id: str
    agent_id: str
    event_count: int = Field(ge=0)
    activity_counts: dict[str, int] = Field(default_factory=dict)
    outcome_counts: dict[str, int] = Field(default_factory=dict)
    anomaly_counts: dict[str, int] = Field(default_factory=dict)
    started_at: datetime
    updated_at: datetime


class SessionInspectionResult(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    event_id: str
    decision: SecurityDecision
    summary: SessionSummary | None = None


@dataclass(slots=True)
class SessionRecord:
    session_id: str
    agent_id: str
    observations: list[RuntimeObservation] = field(default_factory=list)
    last_seen_monotonic: float = 0.0
