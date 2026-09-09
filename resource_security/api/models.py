from dataclasses import dataclass
from enum import StrEnum
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator

from agent_security.identity import is_valid_identity


class HTTPMethod(StrEnum):
    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    PATCH = "PATCH"
    DELETE = "DELETE"


@dataclass(frozen=True, slots=True)
class APIEndpointGrant:
    api_id: str
    method: HTTPMethod
    origin: str
    path: str
    allowed_agents: frozenset[str]
    allowed_query_parameters: frozenset[str] = frozenset()
    allowed_body_fields: frozenset[str] = frozenset()

    def __post_init__(self) -> None:
        if not self.api_id or not self.allowed_agents:
            raise ValueError("API endpoint grant must be explicit")
        if any(not is_valid_identity(agent) for agent in self.allowed_agents):
            raise ValueError("API endpoint identities must be explicit")
        if not self.path.startswith("/") or "?" in self.path or "#" in self.path:
            raise ValueError("API endpoint path must be an exact absolute path")
        origin = urlsplit(self.origin)
        if (
            origin.scheme.casefold() != "https"
            or not origin.hostname
            or origin.username is not None
            or origin.password is not None
            or origin.path not in {"", "/"}
            or origin.query
            or origin.fragment
        ):
            raise ValueError("API origin must be a credential-free HTTPS origin")
        for name in self.allowed_query_parameters | self.allowed_body_fields:
            if not name or not name.replace("_", "a").replace("-", "a").isalnum():
                raise ValueError("API field grants must be explicit names")


class APIAuthorizationRequest(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    api_id: str = Field(pattern=r"^[a-z][a-z0-9_.-]{0,127}$")
    method: HTTPMethod
    url: str = Field(min_length=1, max_length=8192)
    body_fields: tuple[str, ...] = Field(default=(), max_length=128)
    session_id: str | None = Field(default=None, max_length=128)

    @field_validator("body_fields")
    @classmethod
    def validate_body_fields(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(value) != len(set(value)):
            raise ValueError("API body fields must be unique")
        if any(not item or not item.replace("_", "a").replace("-", "a").isalnum() for item in value):
            raise ValueError("API body fields must be explicit names")
        return value
