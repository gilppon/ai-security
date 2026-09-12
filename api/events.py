import asyncio
import json
from collections import deque
from datetime import UTC, datetime
from typing import Any, AsyncGenerator

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, StreamingResponse

router = APIRouter(prefix="/security/events", tags=["events"])

# Bounded ring buffer for recent security events (max 100)
_RECENT_EVENTS: deque[dict[str, Any]] = deque(maxlen=100)
_SUBSCRIBERS: set[asyncio.Queue[dict[str, Any]]] = set()


def broadcast_security_event(event_data: dict[str, Any]) -> None:
    """Broadcast an audit event to all connected SSE subscribers and record in buffer."""
    if "timestamp" not in event_data:
        event_data["timestamp"] = datetime.now(UTC).isoformat()
    _RECENT_EVENTS.append(event_data)
    dead_subscribers: set[asyncio.Queue[dict[str, Any]]] = set()
    for queue in _SUBSCRIBERS:
        try:
            queue.put_nowait(event_data)
        except asyncio.QueueFull:
            dead_subscribers.add(queue)
    _SUBSCRIBERS.difference_update(dead_subscribers)


@router.get("/recent")
async def get_recent_events() -> JSONResponse:
    """Return the recent bounded security events buffer."""
    return JSONResponse(content={"events": list(_RECENT_EVENTS)})


@router.get("/stream")
async def stream_events(request: Request) -> StreamingResponse:
    """Server-Sent Events (SSE) endpoint for real-time security events."""
    queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue(maxsize=100)
    _SUBSCRIBERS.add(queue)

    async def event_generator() -> AsyncGenerator[str, None]:
        # Initial handshake
        yield f"event: handshake\ndata: {json.dumps({'status': 'connected', 'buffered_count': len(_RECENT_EVENTS)})}\n\n"

        # Stream existing buffer if any
        for buffered in list(_RECENT_EVENTS)[-10:]:
            yield f"event: security_event\ndata: {json.dumps(buffered)}\n\n"

        try:
            while True:
                if await request.is_disconnected():
                    break
                try:
                    event = await asyncio.wait_for(queue.get(), timeout=10.0)
                    yield f"event: security_event\ndata: {json.dumps(event)}\n\n"
                except asyncio.TimeoutError:
                    # Keep-alive heartbeat
                    yield ": ping\n\n"
        finally:
            _SUBSCRIBERS.discard(queue)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )
