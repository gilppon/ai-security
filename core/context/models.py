from pydantic import BaseModel, ConfigDict, Field, JsonValue

from core.events.types import TrustLevel


class SecurityContext(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    user_trust: TrustLevel = TrustLevel.UNKNOWN
    agent_trust: TrustLevel = TrustLevel.UNKNOWN
    resource_sensitivity: int = Field(default=0, ge=0, le=40)
    previous_violations: int = Field(default=0, ge=0, le=1000)
    session_attributes: dict[str, JsonValue] = Field(default_factory=dict)
