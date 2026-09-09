from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field


class FilesystemOperation(StrEnum):
    READ = "read"
    WRITE = "write"
    CREATE = "create"
    DELETE = "delete"
    LIST = "list"


@dataclass(frozen=True, slots=True)
class FilesystemGrant:
    root: Path
    operations: frozenset[FilesystemOperation]

    def __post_init__(self) -> None:
        if not self.operations:
            raise ValueError("filesystem grant requires at least one operation")


class FilesystemAuthorizationRequest(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", str_strip_whitespace=False)

    path: str = Field(min_length=1, max_length=4096)
    operation: FilesystemOperation
    session_id: str | None = Field(default=None, max_length=128)

