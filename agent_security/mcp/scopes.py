import re
from collections.abc import Iterable


SCOPE_PATTERN = re.compile(r"^[a-z][a-z0-9_.:-]{0,127}$")
MAX_SCOPES = 64


def validate_scopes(scopes: Iterable[str]) -> tuple[str, ...]:
    values = tuple(scopes)
    if len(values) > MAX_SCOPES:
        raise ValueError("too many MCP scopes")
    if len(values) != len(set(values)):
        raise ValueError("MCP scopes must be unique")
    if any(SCOPE_PATTERN.fullmatch(scope) is None for scope in values):
        raise ValueError("invalid MCP scope")
    return values

