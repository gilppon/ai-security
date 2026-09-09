from typing import Protocol

from agent_security.mcp.manifest import MCPManifest
from agent_security.mcp.models import MCPResultGrant
from core.decisions.reasons import ReasonCode


class MCPManifestRegistryContract(Protocol):
    def get(self, server_id: str) -> MCPManifest | None: ...


class MCPPermissionContract(Protocol):
    def allows(self, agent_id: str, server_id: str, requested_scopes: frozenset[str]) -> bool: ...


class MCPDescriptionScannerContract(Protocol):
    def is_suspicious(self, description: str) -> bool: ...


class MCPResultCapabilityContract(Protocol):
    def issue(
        self,
        *,
        authorization_event_id: str,
        agent_id: str,
        server_id: str,
        tool: str,
        session_id: str | None,
    ) -> str: ...

    def consume(
        self,
        capability: str,
        *,
        agent_id: str,
        server_id: str,
    ) -> tuple[MCPResultGrant | None, ReasonCode | None]: ...
