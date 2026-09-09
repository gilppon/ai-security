from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from pydantic import JsonValue

from core.events.models import SecurityEvent
from core.events.types import TrustLevel


class SecurityEventFactory:
    def create(
        self,
        *,
        event_type: str,
        source: str,
        trust_level: TrustLevel = TrustLevel.UNKNOWN,
        data: dict[str, JsonValue] | None = None,
        **attributes: Any,
    ) -> SecurityEvent:
        return SecurityEvent(
            event_id=f"evt_{uuid4().hex}",
            timestamp=datetime.now(UTC),
            event_type=event_type,
            source=source,
            trust_level=trust_level,
            data=data or {},
            **attributes,
        )
