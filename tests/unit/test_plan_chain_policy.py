import pytest

from agent_security.chaining.confused_deputy import PlanChainPolicy
from agent_security.chaining.models import PlanChainStep
from agent_security.tools.schemas import ToolCapability
from core.decisions.reasons import ReasonCode


def chain_step(
    index: int,
    tool: str,
    capability: ToolCapability,
) -> PlanChainStep:
    return PlanChainStep(
        step_id=f"step-{index}",
        tool=tool,
        capability=capability,
    )


def test_chain_policy_detects_data_source_followed_by_egress() -> None:
    violations = PlanChainPolicy().evaluate((
        chain_step(1, "read_file", ToolCapability.FILESYSTEM),
        chain_step(2, "send_http", ToolCapability.NETWORK),
    ))

    assert tuple(item.reason_code for item in violations) == (
        ReasonCode.PLAN_CONFUSED_DEPUTY,
    )


def test_chain_policy_allows_egress_before_data_source() -> None:
    violations = PlanChainPolicy().evaluate((
        chain_step(1, "fetch", ToolCapability.NETWORK),
        chain_step(2, "write_file", ToolCapability.FILESYSTEM),
    ))

    assert violations == ()


def test_chain_policy_threshold_is_bounded_and_deterministic() -> None:
    policy = PlanChainPolicy(max_repeated_tool_calls=2)
    steps = tuple(
        chain_step(index, "status", ToolCapability.NONE)
        for index in range(3)
    )

    assert policy.evaluate(steps)[0].reason_code is ReasonCode.PLAN_LOOP_DETECTED
    with pytest.raises(ValueError):
        PlanChainPolicy(max_repeated_tool_calls=0)
