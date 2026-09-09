from core.decisions.actions import DecisionAction
from core.events.types import TrustLevel
from content_security.models import SanitizedContentEnvelope
from content_security.utils import fingerprint


RELEASABLE_DECISIONS = {
    DecisionAction.ALLOW,
    DecisionAction.LOG,
    DecisionAction.SANITIZE,
}


class ContextIsolation:
    def release(
        self,
        *,
        sanitized_content: str,
        event_id: str,
        decision: DecisionAction,
        source_trust: TrustLevel,
    ) -> SanitizedContentEnvelope | None:
        if decision not in RELEASABLE_DECISIONS or not sanitized_content:
            return None
        return SanitizedContentEnvelope(
            content=sanitized_content,
            security_event_id=event_id,
            decision=decision,
            content_fingerprint=fingerprint(sanitized_content),
            source_trust=source_trust,
        )

