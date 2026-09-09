from pydantic import BaseModel, ConfigDict, Field

from core.decisions.models import SecurityDecision


class ProcessExecutionResult(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    event_id: str
    authorization_event_id: str | None = None
    decision: SecurityDecision
    exit_code: int | None = None
    stdout_bytes: int = Field(default=0, ge=0)
    stderr_bytes: int = Field(default=0, ge=0)
    stdout_fingerprint: str | None = None
    stderr_fingerprint: str | None = None
