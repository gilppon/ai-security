import os
from typing import Literal

from pydantic import BaseModel, ConfigDict


class Settings(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    service_name: str = "ai-security-control-plane"
    environment: Literal["development", "test", "production"] = "development"
    require_verified_policy: bool = False
    policy_signer_id: str | None = None
    policy_signing_key_hex: str | None = None

    @classmethod
    def from_environment(cls) -> "Settings":
        raw_required = os.environ.get("AI_SECURITY_REQUIRE_VERIFIED_POLICY", "false").lower()
        if raw_required not in {"true", "false"}:
            raise ValueError("AI_SECURITY_REQUIRE_VERIFIED_POLICY must be true or false")
        return cls(
            environment=os.environ.get("AI_SECURITY_ENVIRONMENT", "development"),
            require_verified_policy=raw_required == "true",
            policy_signer_id=os.environ.get("AI_SECURITY_POLICY_SIGNER_ID"),
            policy_signing_key_hex=os.environ.get("AI_SECURITY_POLICY_SIGNING_KEY_HEX"),
        )
