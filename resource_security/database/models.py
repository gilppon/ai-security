from dataclasses import dataclass
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field, field_validator

from agent_security.identity import is_valid_identity


class DatabaseOperation(StrEnum):
    SELECT = "select"
    INSERT = "insert"
    UPDATE = "update"
    DELETE = "delete"


@dataclass(frozen=True, slots=True)
class DatabaseTableGrant:
    table: str
    operations: frozenset[DatabaseOperation]
    columns: frozenset[str]
    predicate_fields: frozenset[str] = frozenset()

    def __post_init__(self) -> None:
        if not self.table or not self.operations or not self.columns:
            raise ValueError("database table grant must be explicit")
        if not self.predicate_fields.issubset(self.columns):
            raise ValueError("predicate fields must be granted columns")


@dataclass(frozen=True, slots=True)
class DatabaseGrant:
    database_id: str
    allowed_agents: frozenset[str]
    tables: tuple[DatabaseTableGrant, ...]

    def __post_init__(self) -> None:
        if not self.database_id or not self.allowed_agents or not self.tables:
            raise ValueError("database grant must be explicit")
        if any(not is_valid_identity(agent) for agent in self.allowed_agents):
            raise ValueError("database grant identities must be explicit")
        names = tuple(item.table for item in self.tables)
        if len(names) != len(set(names)):
            raise ValueError("database table grants must be unique")


class DatabaseAuthorizationRequest(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    database_id: str = Field(pattern=r"^[a-z][a-z0-9_.-]{0,127}$")
    operation: DatabaseOperation
    table: str = Field(pattern=r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")
    columns: tuple[str, ...] = Field(min_length=1, max_length=128)
    predicate_fields: tuple[str, ...] = Field(default=(), max_length=64)
    session_id: str | None = Field(default=None, max_length=128)

    @field_validator("columns", "predicate_fields")
    @classmethod
    def validate_identifiers(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(value) != len(set(value)):
            raise ValueError("database fields must be unique")
        if any(
            not item
            or not item.replace("_", "a").isalnum()
            or not (item[0].isalpha() or item[0] == "_")
            for item in value
        ):
            raise ValueError("database fields must be identifiers")
        return value
