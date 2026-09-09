from typing import Any

from core.events.models import SecurityEvent


class EventNormalizer:
    def normalize(self, event: SecurityEvent) -> SecurityEvent:
        normalized_data = self._normalize_mapping(event.data)
        return event.model_copy(update={
            "event_type": event.event_type.strip().lower(),
            "source": event.source.strip().lower(),
            "target": event.target.strip().lower() if event.target else None,
            "action": event.action.strip().lower() if event.action else None,
            "data": normalized_data,
        })

    def _normalize_mapping(self, value: dict[str, Any]) -> dict[str, Any]:
        return {str(key).strip(): item for key, item in value.items()}

