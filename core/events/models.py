from datetime import datetime
from pydantic import BaseModel, ConfigDict, Field, JsonValue, field_validator

from core.events.types import TrustLevel


class SecurityEvent(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    event_id: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9_.:-]+$")
    timestamp: datetime
    event_type: str = Field(min_length=3, max_length=128, pattern=r"^[a-z0-9]+(?:[._-][a-z0-9]+)+$")
    session_id: str | None = Field(default=None, max_length=128)
    user_id: str | None = Field(default=None, max_length=128)
    agent_id: str | None = Field(default=None, max_length=128)
    source: str = Field(min_length=1, max_length=128)
    target: str | None = Field(default=None, max_length=256)
    action: str | None = Field(default=None, max_length=128)
    resource_type: str | None = Field(default=None, max_length=128)
    resource: str | None = Field(default=None, max_length=2048)
    data: dict[str, JsonValue] = Field(default_factory=dict)
    trust_level: TrustLevel = TrustLevel.UNKNOWN
    risk_score: int = Field(default=0, ge=0, le=100)

    @field_validator("timestamp")
    @classmethod
    def require_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("timestamp must be timezone-aware")
        return value
