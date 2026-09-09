from dataclasses import dataclass

from agent_security.tools.schemas import ToolCapability
from core.decisions.reasons import ReasonCode


@dataclass(frozen=True, slots=True)
class PlanChainStep:
    step_id: str
    tool: str
    capability: ToolCapability


@dataclass(frozen=True, slots=True)
class PlanChainViolation:
    rule_id: str
    reason_code: ReasonCode
