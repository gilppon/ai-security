from pydantic import BaseModel, ConfigDict, Field, JsonValue, field_validator

from core.decisions.actions import DecisionAction
from core.decisions.reasons import ReasonCode


class SecurityDecision(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    decision: DecisionAction
    risk_score: int = Field(ge=0, le=100)
    reason_codes: tuple[ReasonCode, ...]
    matched_rules: tuple[str, ...] = ()
    metadata: dict[str, JsonValue] = Field(default_factory=dict)

    @field_validator("reason_codes")
    @classmethod
    def require_reason_codes(cls, value: tuple[ReasonCode, ...]) -> tuple[ReasonCode, ...]:
        if not value:
            raise ValueError("every decision requires at least one reason code")
        return value

    @classmethod
    def default_deny(cls, *, risk_score: int = 0) -> "SecurityDecision":
        return cls(
            decision=DecisionAction.DENY,
            risk_score=risk_score,
            reason_codes=(ReasonCode.DEFAULT_DENY,),
        )
