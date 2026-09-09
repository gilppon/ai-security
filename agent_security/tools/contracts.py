from typing import Protocol

from pydantic import JsonValue

from agent_security.tools.schemas import ToolAuthorizationResult, ToolAuthorizeRequest, ToolDefinition


class ToolRegistryContract(Protocol):
    def get(self, name: str) -> ToolDefinition | None: ...


class ToolArgumentValidatorContract(Protocol):
    def validate(
        self,
        definition: ToolDefinition,
        arguments: dict[str, JsonValue],
    ) -> tuple[str, ...]: ...


class ToolAuthorizerContract(Protocol):
    def authorize(
        self,
        request: ToolAuthorizeRequest,
        *,
        verified_agent_id: str | None = None,
    ) -> ToolAuthorizationResult: ...

