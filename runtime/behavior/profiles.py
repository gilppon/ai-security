from dataclasses import dataclass

from agent_security.identity import is_valid_identity
from runtime.models import RuntimeActivity


@dataclass(frozen=True, slots=True)
class BehaviorProfile:
    agent_id: str
    allowed_activities: frozenset[RuntimeActivity]
    window_seconds: int = 60
    max_events_per_window: int = 60
    max_denied_per_window: int = 5
    max_distinct_targets_per_window: int = 20

    def __post_init__(self) -> None:
        if not is_valid_identity(self.agent_id):
            raise ValueError("behavior profile requires an explicit agent identity")
        if not self.allowed_activities:
            raise ValueError("behavior profile requires allowed activities")
        if not 1 <= self.window_seconds <= 3600:
            raise ValueError("behavior window must be between 1 and 3600 seconds")
        if not 1 <= self.max_events_per_window <= 10_000:
            raise ValueError("event threshold is outside supported bounds")
        if not 1 <= self.max_denied_per_window <= self.max_events_per_window:
            raise ValueError("denial threshold is outside supported bounds")
        if not 1 <= self.max_distinct_targets_per_window <= self.max_events_per_window:
            raise ValueError("target threshold is outside supported bounds")
