import pytest
from pydantic import ValidationError

from agent_security.planner.models import (
    AgentPlanRequest,
    MAX_PLAN_ARGUMENT_BYTES,
    MAX_PLAN_STEPS,
    PlanStep,
)


def step(index: int) -> PlanStep:
    return PlanStep(step_id=f"step-{index}", tool="status", arguments={})


def test_plan_requires_unique_step_ids_and_bounded_steps() -> None:
    with pytest.raises(ValidationError, match="unique"):
        AgentPlanRequest(
            plan_id="plan-1",
            session_id="session-1",
            steps=(step(1), step(1)),
        )

    with pytest.raises(ValidationError):
        AgentPlanRequest(
            plan_id="plan-1",
            session_id="session-1",
            steps=tuple(step(index) for index in range(MAX_PLAN_STEPS + 1)),
        )


def test_plan_cannot_self_assert_agent_identity_or_trust() -> None:
    with pytest.raises(ValidationError):
        AgentPlanRequest.model_validate({
            "plan_id": "plan-1",
            "session_id": "session-1",
            "steps": [{"step_id": "step-1", "tool": "status"}],
            "agent_id": "agent-1",
            "trust_level": "trusted",
        })


def test_plan_step_rejects_oversized_nested_arguments() -> None:
    with pytest.raises(ValidationError, match="size limit"):
        PlanStep(
            step_id="step-large",
            tool="status",
            arguments={"nested": {"value": "x" * MAX_PLAN_ARGUMENT_BYTES}},
        )
