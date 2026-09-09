from core.context.models import SecurityContext
from core.events.models import SecurityEvent


class SecurityContextBuilder:
    def build(self, event: SecurityEvent) -> SecurityContext:
        return SecurityContext(
            user_trust=event.trust_level,
            agent_trust=event.trust_level,
        )

