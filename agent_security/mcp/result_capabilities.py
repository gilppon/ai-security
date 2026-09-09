import secrets
import threading
import time
from collections.abc import Callable

from agent_security.identity import is_valid_identity
from agent_security.mcp.models import MCPResultGrant
from core.decisions.reasons import ReasonCode


class MCPResultCapabilityStore:
    def __init__(
        self,
        *,
        ttl_seconds: float = 60,
        max_active: int = 10_000,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if not 1 <= ttl_seconds <= 300:
            raise ValueError("MCP result capability TTL is outside supported bounds")
        if not 1 <= max_active <= 100_000:
            raise ValueError("MCP result capability capacity is outside supported bounds")
        self._ttl_seconds = ttl_seconds
        self._max_active = max_active
        self._clock = clock
        self._active: dict[str, MCPResultGrant] = {}
        self._terminal: dict[str, tuple[ReasonCode, float]] = {}
        self._lock = threading.RLock()

    def issue(
        self,
        *,
        authorization_event_id: str,
        agent_id: str,
        server_id: str,
        tool: str,
        session_id: str | None,
    ) -> str:
        if not is_valid_identity(agent_id) or not is_valid_identity(server_id):
            raise ValueError("MCP result capability requires verified identities")
        with self._lock:
            now = self._clock()
            self._purge(now)
            if len(self._active) >= self._max_active:
                raise RuntimeError("MCP result capability capacity reached")
            capability = secrets.token_urlsafe(32)
            while capability in self._active or capability in self._terminal:
                capability = secrets.token_urlsafe(32)
            self._active[capability] = MCPResultGrant(
                authorization_event_id=authorization_event_id,
                agent_id=agent_id,
                server_id=server_id,
                tool=tool,
                session_id=session_id,
                expires_at=now + self._ttl_seconds,
            )
            return capability

    def consume(
        self,
        capability: str,
        *,
        agent_id: str,
        server_id: str,
    ) -> tuple[MCPResultGrant | None, ReasonCode | None]:
        with self._lock:
            now = self._clock()
            self._purge(now)
            terminal = self._terminal.get(capability)
            if terminal is not None:
                return None, terminal[0]
            grant = self._active.get(capability)
            if grant is None:
                return None, ReasonCode.MCP_RESULT_CAPABILITY_INVALID
            if grant.agent_id != agent_id or grant.server_id != server_id:
                return None, ReasonCode.MCP_RESULT_IDENTITY_MISMATCH
            del self._active[capability]
            self._remember(capability, ReasonCode.MCP_RESULT_CAPABILITY_REPLAYED, now)
            return grant, None

    def _purge(self, now: float) -> None:
        expired = [
            capability
            for capability, grant in self._active.items()
            if now > grant.expires_at
        ]
        for capability in expired:
            del self._active[capability]
            self._remember(capability, ReasonCode.MCP_RESULT_CAPABILITY_EXPIRED, now)
        stale = [
            capability
            for capability, (_, retain_until) in self._terminal.items()
            if now > retain_until
        ]
        for capability in stale:
            del self._terminal[capability]

    def _remember(self, capability: str, reason: ReasonCode, now: float) -> None:
        if len(self._terminal) >= self._max_active:
            oldest = min(self._terminal, key=lambda item: self._terminal[item][1])
            del self._terminal[oldest]
        self._terminal[capability] = (reason, now + self._ttl_seconds)
