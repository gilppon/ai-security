from collections.abc import Callable

from core.events.models import SecurityEvent

EventHandler = Callable[[SecurityEvent], None]


class InMemoryEventBus:
    def __init__(self) -> None:
        self._handlers: list[EventHandler] = []

    def subscribe(self, handler: EventHandler) -> None:
        self._handlers.append(handler)

    def publish(self, event: SecurityEvent) -> None:
        for handler in tuple(self._handlers):
            handler(event)

