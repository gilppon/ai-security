from pydantic import BaseModel, ConfigDict, Field, model_validator


class RiskContribution(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    source: str = Field(min_length=1, max_length=128)
    score: int = Field(ge=0, le=100)
    reason_code: str = Field(min_length=1, max_length=128, pattern=r"^[A-Z][A-Z0-9_]+$")


class RiskScore(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    total: int = Field(ge=0, le=100)
    contributions: tuple[RiskContribution, ...] = ()

    @model_validator(mode="after")
    def total_matches_contributions(self) -> "RiskScore":
        expected = min(100, sum(item.score for item in self.contributions))
        if self.total != expected:
            raise ValueError("total must equal capped contribution sum")
        return self

