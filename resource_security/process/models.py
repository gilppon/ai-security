from dataclasses import dataclass
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field, field_validator

from core.decisions.models import SecurityDecision


@dataclass(frozen=True, slots=True)
class ProcessGrant:
    executable: Path
    argument_prefix: tuple[str, ...]
    working_roots: tuple[Path, ...]
    path_argument_indices: tuple[int, ...] = ()
    max_timeout_seconds: float = 30.0
    max_output_bytes: int = 1_048_576

    def __post_init__(self) -> None:
        if not self.executable.is_absolute():
            raise ValueError("process executable grant must be absolute")
        if not self.working_roots or any(not root.is_absolute() for root in self.working_roots):
            raise ValueError("process grant requires absolute working roots")
        if not 0.1 <= self.max_timeout_seconds <= 300:
            raise ValueError("process timeout grant must be between 0.1 and 300 seconds")
        if not 1_024 <= self.max_output_bytes <= 16_777_216:
            raise ValueError("process output grant is outside supported bounds")
        if any(index < 1 for index in self.path_argument_indices):
            raise ValueError("path argument indices exclude argv[0]")
        if len(self.path_argument_indices) != len(set(self.path_argument_indices)):
            raise ValueError("path argument indices must be unique")
        if set(self.path_argument_indices).intersection(range(1, len(self.argument_prefix) + 1)):
            raise ValueError("literal and path argument positions cannot overlap")


class ProcessAuthorizationRequest(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", str_strip_whitespace=False)

    argv: tuple[str, ...] = Field(min_length=1, max_length=128)
    working_directory: str = Field(min_length=1, max_length=4096)
    timeout_seconds: float = Field(default=30.0, ge=0.1, le=300)
    session_id: str | None = Field(default=None, max_length=128)

    @field_validator("argv")
    @classmethod
    def validate_argv(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if any(not item or len(item) > 8192 or "\x00" in item for item in value):
            raise ValueError("argv contains an invalid argument")
        return value


class ProcessAuthorizationResult(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    event_id: str
    decision: SecurityDecision
    capability: str | None = None


@dataclass(frozen=True, slots=True)
class AuthorizedProcessSpec:
    authorization_event_id: str
    executable: Path
    argv: tuple[str, ...]
    working_directory: Path
    timeout_seconds: float
    max_output_bytes: int
    session_id: str | None
    expires_at: float
