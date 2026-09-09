import json
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, JsonValue, model_validator

from agent_security.tools.schemas import ToolCapability
from core.decisions.models import SecurityDecision
from core.decisions.reasons import ReasonCode


MAX_PLAN_STEPS = 32
MAX_PLAN_ARGUMENT_BYTES = 65_536
MAX_PLAN_BYTES = 262_144


class PlanStep(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    step_id: str = Field(
        min_length=1,
        max_length=64,
        pattern=r"^[a-z0-9]+(?:[._-][a-z0-9]+)*$",
    )
    tool: str = Field(pattern=r"^[a-z][a-z0-9_.-]{0,127}$")
    arguments: dict[str, JsonValue] = Field(default_factory=dict, max_length=64)

    @model_validator(mode="after")
    def bound_argument_size(self) -> "PlanStep":
        if _json_size(self.arguments) > MAX_PLAN_ARGUMENT_BYTES:
            raise ValueError("plan step arguments exceed size limit")
        return self


class AgentPlanRequest(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    plan_id: str = Field(
        min_length=3,
        max_length=128,
        pattern=r"^[a-z0-9]+(?:[._-][a-z0-9]+)*$",
    )
    session_id: str = Field(
        min_length=1,
        max_length=128,
        pattern=r"^[A-Za-z0-9_.:-]+$",
    )
    steps: tuple[PlanStep, ...] = Field(min_length=1, max_length=MAX_PLAN_STEPS)

    @model_validator(mode="after")
    def require_unique_step_ids(self) -> "AgentPlanRequest":
        step_ids = [step.step_id for step in self.steps]
        if len(step_ids) != len(set(step_ids)):
            raise ValueError("plan step ids must be unique")
        if _json_size(self.model_dump(mode="json")) > MAX_PLAN_BYTES:
            raise ValueError("agent plan exceeds size limit")
        return self


class PlanStepAssessment(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    step_id: str
    tool: str
    capability: ToolCapability | None = None
    precheck_passed: bool
    reason_codes: tuple[ReasonCode, ...] = Field(min_length=1)


class PlanValidationResult(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    event_id: str
    plan_id: str
    plan_fingerprint: str = Field(pattern=r"^[a-f0-9]{16}$")
    decision: SecurityDecision
    step_count: int = Field(ge=1, le=MAX_PLAN_STEPS)
    step_assessments: tuple[PlanStepAssessment, ...]
    execution_authorized: Literal[False] = False


def _json_size(value: object) -> int:
    return len(json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8"))
