import os
from typing import Literal

from pydantic import BaseModel, ConfigDict, SecretStr


class Settings(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    service_name: str = "ai-security-control-plane"
    environment: Literal["development", "test", "production"] = "development"
    require_verified_policy: bool = False
    policy_signer_id: str | None = None
    policy_signing_key_hex: SecretStr | None = None
    policy_approver_id: str | None = None
    policy_approval_key_hex: SecretStr | None = None
    policy_signing_keys_json: SecretStr | None = None
    policy_approval_keys_json: SecretStr | None = None
    policy_revoked_signer_ids: tuple[str, ...] = ()
    policy_revoked_approver_ids: tuple[str, ...] = ()
    policy_store_path: str | None = None

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
            policy_approver_id=os.environ.get("AI_SECURITY_POLICY_APPROVER_ID"),
            policy_approval_key_hex=os.environ.get("AI_SECURITY_POLICY_APPROVAL_KEY_HEX"),
            policy_signing_keys_json=os.environ.get("AI_SECURITY_POLICY_SIGNING_KEYS_JSON"),
            policy_approval_keys_json=os.environ.get("AI_SECURITY_POLICY_APPROVAL_KEYS_JSON"),
            policy_revoked_signer_ids=_csv_environment("AI_SECURITY_POLICY_REVOKED_SIGNER_IDS"),
            policy_revoked_approver_ids=_csv_environment("AI_SECURITY_POLICY_REVOKED_APPROVER_IDS"),
            policy_store_path=os.environ.get("AI_SECURITY_POLICY_STORE_PATH"),
        )


def _csv_environment(name: str) -> tuple[str, ...]:
    return tuple(item.strip() for item in os.environ.get(name, "").split(",") if item.strip())
