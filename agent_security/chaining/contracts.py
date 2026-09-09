from typing import Protocol

from agent_security.chaining.models import PlanChainStep, PlanChainViolation


class PlanChainPolicyContract(Protocol):
    def evaluate(
        self,
        steps: tuple[PlanChainStep, ...],
    ) -> tuple[PlanChainViolation, ...]: ...
