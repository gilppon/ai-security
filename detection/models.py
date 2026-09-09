from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, model_validator


class Severity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class RuleAction(StrEnum):
    ALLOW = "allow"
    LOG = "log"
    SANITIZE = "sanitize"
    APPROVAL_REQUIRED = "approval_required"
    DENY = "deny"
    QUARANTINE = "quarantine"
    TERMINATE = "terminate"
    AUDIT = "audit"
    ALERT = "alert"


class RuleRisk(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    score: int = Field(ge=0, le=100)


class AISecRule(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    id: str = Field(pattern=r"^ASEC-[A-Z0-9]+(?:-[A-Z0-9]+)*$")
    title: str = Field(min_length=1, max_length=256)
    category: str = Field(min_length=1, max_length=64, pattern=r"^[a-z][a-z0-9_]*$")
    severity: Severity
    when: dict[str, Any] = Field(min_length=1)
    match: dict[str, Any] = Field(default_factory=dict)
    unless: dict[str, Any] = Field(default_factory=dict)
    risk: RuleRisk
    actions: tuple[RuleAction, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def prevent_ambiguous_fields(self) -> "AISecRule":
        overlap = set(self.when) & set(self.match)
        if overlap:
            raise ValueError(f"fields cannot appear in both when and match: {sorted(overlap)}")
        return self


class DetectionFinding(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    rule_id: str
    severity: Severity
    risk_score: int = Field(ge=0, le=100)
    actions: tuple[RuleAction, ...]
    reason_codes: tuple[str, ...] = ("RULE_MATCHED",)
