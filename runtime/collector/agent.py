from core.decisions.actions import DecisionAction
from core.decisions.models import SecurityDecision
from core.events.models import SecurityEvent
from runtime.models import (
    RuntimeActivity,
    RuntimeEventRequest,
    RuntimeObservationResult,
    RuntimeOutcome,
)
from runtime.monitor import RuntimeMonitor


_ALLOWED_FINGERPRINT_KEYS = (
    "api_fingerprint",
    "database_fingerprint",
    "executable_fingerprint",
    "path_fingerprint",
    "tool_fingerprint",
    "url_fingerprint",
)


class RuntimeCollector:
    def __init__(self, monitor: RuntimeMonitor) -> None:
        self._monitor = monitor

    def collect(
        self,
        event: SecurityEvent,
        decision: SecurityDecision,
        activity: RuntimeActivity,
        *,
        verified_agent_id: str | None = None,
    ) -> RuntimeObservationResult:
        if event.session_id is None:
            raise ValueError("runtime collection requires a session id")
        target_fingerprint = next(
            (
                value
                for key in _ALLOWED_FINGERPRINT_KEYS
                if isinstance((value := event.data.get(key)), str)
                and len(value) == 16
                and all(character in "0123456789abcdef" for character in value)
            ),
            None,
        )
        blocked = decision.decision in {
            DecisionAction.APPROVAL_REQUIRED,
            DecisionAction.DENY,
            DecisionAction.QUARANTINE,
            DecisionAction.TERMINATE,
        }
        identity_matches = (
            event.agent_id is None or event.agent_id == verified_agent_id
        )
        return self._monitor.observe(
            RuntimeEventRequest(
                session_id=event.session_id,
                activity=activity,
                outcome=RuntimeOutcome.BLOCKED if blocked else RuntimeOutcome.ALLOWED,
                target_fingerprint=target_fingerprint,
                source_event_id=event.event_id,
            ),
            verified_agent_id=verified_agent_id if identity_matches else None,
        )
