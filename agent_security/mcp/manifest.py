from collections.abc import Iterable

from pydantic import BaseModel, ConfigDict, Field, model_validator

from agent_security.mcp.scopes import validate_scopes


class MCPToolManifest(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    name: str = Field(pattern=r"^[a-z][a-z0-9_.-]{0,127}$")
    local_tool_name: str = Field(pattern=r"^[a-z][a-z0-9_.-]{0,127}$")
    description: str = Field(min_length=1, max_length=2048)
    declared_scopes: tuple[str, ...] = Field(default=(), max_length=64)

    @model_validator(mode="after")
    def unique_scopes(self) -> "MCPToolManifest":
        validate_scopes(self.declared_scopes)
        return self


class MCPManifest(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    server_id: str = Field(pattern=r"^[a-z][a-z0-9_.-]{0,127}$")
    version: str = Field(min_length=1, max_length=64)
    tools: tuple[MCPToolManifest, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def unique_tools(self) -> "MCPManifest":
        names = [tool.name for tool in self.tools]
        if len(names) != len(set(names)):
            raise ValueError("MCP tool names must be unique")
        return self


class MCPManifestRegistry:
    def __init__(self, manifests: Iterable[MCPManifest] = ()) -> None:
        self._manifests: dict[str, MCPManifest] = {}
        self._tool_cache: dict[tuple[str, str], MCPToolManifest | None] = {}
        for manifest in manifests:
            self.register(manifest)

    def register(self, manifest: MCPManifest) -> None:
        if manifest.server_id in self._manifests:
            raise ValueError(f"MCP server already registered: {manifest.server_id}")
        self._manifests[manifest.server_id] = manifest
        # Populate / invalidate tool lookup cache for this server
        for tool in manifest.tools:
            self._tool_cache[(manifest.server_id, tool.name)] = tool

    def get(self, server_id: str) -> MCPManifest | None:
        return self._manifests.get(server_id)

    def get_tool(self, server_id: str, tool_name: str) -> MCPToolManifest | None:
        cache_key = (server_id, tool_name)
        if cache_key in self._tool_cache:
            return self._tool_cache[cache_key]
        manifest = self.get(server_id)
        if manifest is None:
            self._tool_cache[cache_key] = None
            return None
        for tool in manifest.tools:
            if tool.name == tool_name:
                self._tool_cache[cache_key] = tool
                return tool
        self._tool_cache[cache_key] = None
        return None
