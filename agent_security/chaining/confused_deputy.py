from collections import Counter

from agent_security.chaining.models import PlanChainStep, PlanChainViolation
from agent_security.tools.schemas import ToolCapability
from core.decisions.reasons import ReasonCode


MAX_REPEATED_TOOL_CALLS = 5
_DATA_SOURCE_CAPABILITIES = frozenset({
    ToolCapability.FILESYSTEM,
    ToolCapability.DATABASE,
})
_EGRESS_CAPABILITIES = frozenset({
    ToolCapability.NETWORK,
    ToolCapability.API,
})


class PlanChainPolicy:
    def __init__(self, *, max_repeated_tool_calls: int = MAX_REPEATED_TOOL_CALLS) -> None:
        if not 1 <= max_repeated_tool_calls <= 32:
            raise ValueError("repeated tool threshold is outside supported bounds")
        self._max_repeated_tool_calls = max_repeated_tool_calls

    def evaluate(
        self,
        steps: tuple[PlanChainStep, ...],
    ) -> tuple[PlanChainViolation, ...]:
        violations: list[PlanChainViolation] = []
        if any(
            count > self._max_repeated_tool_calls
            for count in Counter(step.tool for step in steps).values()
        ):
            violations.append(PlanChainViolation(
                rule_id="ASEC-PLAN-LOOP-001",
                reason_code=ReasonCode.PLAN_LOOP_DETECTED,
            ))

        seen_data_source = False
        for step in steps:
            if step.capability in _DATA_SOURCE_CAPABILITIES:
                seen_data_source = True
            elif seen_data_source and step.capability in _EGRESS_CAPABILITIES:
                violations.append(PlanChainViolation(
                    rule_id="ASEC-PLAN-CONFUSED-DEPUTY-001",
                    reason_code=ReasonCode.PLAN_CONFUSED_DEPUTY,
                ))
                break
        return tuple(violations)
