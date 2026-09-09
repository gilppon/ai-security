from dataclasses import dataclass

from pydantic import BaseModel, ConfigDict, Field, JsonValue, model_validator

from core.decisions.models import SecurityDecision
from agent_security.mcp.scopes import validate_scopes


class MCPAuthorizeRequest(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    server_id: str = Field(pattern=r"^[a-z][a-z0-9_.-]{0,127}$")
    server_version: str = Field(min_length=1, max_length=64)
    tool: str = Field(pattern=r"^[a-z][a-z0-9_.-]{0,127}$")
    arguments: dict[str, JsonValue] = Field(default_factory=dict, max_length=64)
    requested_scopes: tuple[str, ...] = Field(default=(), max_length=64)
    session_id: str | None = Field(default=None, max_length=128)

    @model_validator(mode="after")
    def unique_scopes(self) -> "MCPAuthorizeRequest":
        validate_scopes(self.requested_scopes)
        return self


class MCPAuthorizationResult(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    event_id: str
    decision: SecurityDecision
    server_id: str
    tool: str
    tool_authorization_event_id: str | None = None
    result_capability: str | None = None


class MCPResultRequest(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", str_strip_whitespace=False)

    result_capability: str = Field(min_length=32, max_length=512)
    content: str = Field(min_length=1, max_length=262_144)


class MCPResultInspectionResult(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    event_id: str
    decision: SecurityDecision
    authorization_event_id: str | None = None
    content_event_id: str | None = None
    output_event_id: str | None = None
    result_fingerprint: str = Field(pattern=r"^[a-f0-9]{16}$")
    released_fingerprint: str | None = Field(default=None, pattern=r"^[a-f0-9]{16}$")
    released_result: str | None = None


@dataclass(frozen=True, slots=True)
class MCPResultGrant:
    authorization_event_id: str
    agent_id: str
    server_id: str
    tool: str
    session_id: str | None
    expires_at: float
