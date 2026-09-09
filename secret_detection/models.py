from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field, model_validator

from detection.models import Severity


class SecretCategory(StrEnum):
    API_KEY = "API_KEY"
    GIT_TOKEN = "GIT_TOKEN"
    CLOUD_ACCESS_KEY = "CLOUD_ACCESS_KEY"
    JWT = "JWT"
    PRIVATE_KEY = "PRIVATE_KEY"
    DATABASE_CREDENTIAL = "DATABASE_CREDENTIAL"
    GENERIC_CREDENTIAL = "GENERIC_CREDENTIAL"


class SecretLocation(StrEnum):
    README = "README"
    TEST_FIXTURE = "TEST_FIXTURE"
    SOURCE_CODE = "SOURCE_CODE"
    ENV_FILE = "ENV_FILE"
    PRODUCTION_OUTPUT = "PRODUCTION_OUTPUT"
    UNKNOWN = "UNKNOWN"


class SecretFinding(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    code: str = Field(pattern=r"^SECRET_[A-Z_]+$")
    category: SecretCategory
    severity: Severity
    risk_score: int = Field(ge=0, le=100)
    detector: str = Field(min_length=1, max_length=64)
    evidence_fingerprint: str = Field(pattern=r"^[a-f0-9]{16}$")
    entropy: float = Field(ge=0, le=8)
    location: SecretLocation
    start: int = Field(ge=0, exclude=True)
    end: int = Field(gt=0, exclude=True)

    @model_validator(mode="after")
    def validate_span(self) -> "SecretFinding":
        if self.end <= self.start:
            raise ValueError("secret finding span must be non-empty")
        return self
