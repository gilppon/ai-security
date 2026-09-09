from pydantic import BaseModel, ConfigDict, Field

from core.events.types import TrustLevel


class SourceTrustAssessment(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    trust_level: TrustLevel
    risk_score: int = Field(ge=0, le=100)
    reason_code: str = Field(pattern=r"^[A-Z][A-Z0-9_]+$")

