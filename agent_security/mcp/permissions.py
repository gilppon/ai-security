from collections.abc import Iterable
from dataclasses import dataclass

from agent_security.mcp.scopes import validate_scopes
from agent_security.identity import is_valid_identity


@dataclass(frozen=True, slots=True)
class MCPPermissionGrant:
    agent_id: str
    server_id: str
    scopes: frozenset[str]

    def __post_init__(self) -> None:
        if not is_valid_identity(self.agent_id) or not is_valid_identity(self.server_id):
            raise ValueError("MCP permission grant requires agent and server identities")
        validate_scopes(self.scopes)


class MCPPermissionModel:
    def __init__(self, grants: Iterable[MCPPermissionGrant] = ()) -> None:
        self._grants: dict[tuple[str, str], frozenset[str]] = {}
        for grant in grants:
            key = (grant.agent_id, grant.server_id)
            if key in self._grants:
                raise ValueError("duplicate MCP permission grant")
            self._grants[key] = grant.scopes

    def allows(self, agent_id: str, server_id: str, requested_scopes: frozenset[str]) -> bool:
        key = (agent_id, server_id)
        return key in self._grants and requested_scopes.issubset(self._grants[key])
