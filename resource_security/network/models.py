from dataclasses import dataclass

from pydantic import BaseModel, ConfigDict, Field


@dataclass(frozen=True, slots=True)
class NetworkGrant:
    host_pattern: str
    ports: frozenset[int] = frozenset({443})

    def __post_init__(self) -> None:
        normalized = self.host_pattern.casefold().rstrip(".")
        if not normalized or normalized == "*" or "/" in normalized:
            raise ValueError("network host pattern must be exact or a scoped wildcard")
        if "*" in normalized and not normalized.startswith("*."):
            raise ValueError("wildcard is allowed only as a leading label")
        if normalized.startswith("*."):
            suffix = normalized[2:]
            if "." not in suffix:
                raise ValueError("wildcard must be scoped below a registrable-style domain")
            normalized = "*." + suffix.encode("idna").decode("ascii")
        else:
            normalized = normalized.encode("idna").decode("ascii")
        if not self.ports or any(port < 1 or port > 65535 for port in self.ports):
            raise ValueError("network grant ports are invalid")
        object.__setattr__(self, "host_pattern", normalized)


class NetworkAuthorizationRequest(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", str_strip_whitespace=False)

    url: str = Field(min_length=1, max_length=4096)
    session_id: str | None = Field(default=None, max_length=128)
