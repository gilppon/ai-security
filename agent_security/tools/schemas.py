from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field, JsonValue, model_validator

from core.decisions.models import SecurityDecision
from agent_security.identity import is_valid_identity
from resource_security.filesystem.models import FilesystemOperation


class ToolCapability(StrEnum):
    NONE = "none"
    FILESYSTEM = "filesystem"
    NETWORK = "network"
    PROCESS = "process"
    DATABASE = "database"
    API = "api"


class ArgumentType(StrEnum):
    STRING = "string"
    INTEGER = "integer"
    NUMBER = "number"
    BOOLEAN = "boolean"
    OBJECT = "object"
    ARRAY = "array"


class ToolArgumentSpec(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    name: str = Field(pattern=r"^[a-z][a-z0-9_]{0,63}$")
    argument_type: ArgumentType
    required: bool = True
    max_length: int = Field(default=4096, ge=1, le=65_536)
    allowed_values: tuple[JsonValue, ...] = ()


class ToolDefinition(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    name: str = Field(pattern=r"^[a-z][a-z0-9_.-]{0,127}$")
    capability: ToolCapability
    arguments: tuple[ToolArgumentSpec, ...] = ()
    allowed_agents: tuple[str, ...] = Field(min_length=1, max_length=64)
    resource_argument: str | None = None
    filesystem_operation: FilesystemOperation | None = None

    @model_validator(mode="after")
    def validate_definition(self) -> "ToolDefinition":
        names = [item.name for item in self.arguments]
        if len(names) != len(set(names)):
            raise ValueError("tool argument names must be unique")
        if len(self.allowed_agents) != len(set(self.allowed_agents)):
            raise ValueError("tool agent identities must be unique")
        if any(not is_valid_identity(agent) for agent in self.allowed_agents):
            raise ValueError("tool grants require explicit agent identities")
        if self.capability in {
            ToolCapability.FILESYSTEM,
            ToolCapability.NETWORK,
            ToolCapability.PROCESS,
            ToolCapability.DATABASE,
            ToolCapability.API,
        }:
            if self.resource_argument not in names:
                raise ValueError("resource capability requires a declared resource argument")
            resource_spec = next(item for item in self.arguments if item.name == self.resource_argument)
            expected_type = (
                ArgumentType.STRING
                if self.capability in {ToolCapability.FILESYSTEM, ToolCapability.NETWORK}
                else ArgumentType.OBJECT
            )
            if resource_spec.argument_type is not expected_type:
                raise ValueError(f"resource argument must be {expected_type.value}")
        if self.capability is ToolCapability.FILESYSTEM and self.filesystem_operation is None:
            raise ValueError("filesystem tool requires an operation")
        if self.capability is not ToolCapability.FILESYSTEM and self.filesystem_operation is not None:
            raise ValueError("filesystem operation is valid only for filesystem tools")
        return self


class ToolAuthorizeRequest(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    tool: str = Field(pattern=r"^[a-z][a-z0-9_.-]{0,127}$")
    arguments: dict[str, JsonValue] = Field(default_factory=dict, max_length=64)
    session_id: str | None = Field(default=None, max_length=128)


class ToolAuthorizationResult(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    event_id: str
    decision: SecurityDecision
    tool: str
    resource_authorization_event_id: str | None = None
    process_capability: str | None = None
