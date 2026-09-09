import pytest

from app.config import Settings
from app.policy_startup import activate_policy_or_raise, verifier_from_settings


def test_unconfigured_development_startup_does_not_require_policy() -> None:
    settings = Settings()

    assert verifier_from_settings(settings) is None
    activate_policy_or_raise(settings, None)


def test_production_startup_requires_verified_policy() -> None:
    settings = Settings(environment="production")

    with pytest.raises(RuntimeError, match="production startup requires verified policy"):
        verifier_from_settings(settings)


def test_verified_startup_requires_key_and_service() -> None:
    settings = Settings(require_verified_policy=True)

    with pytest.raises(RuntimeError, match="signer id and key"):
        activate_policy_or_raise(settings, None)


def test_invalid_key_is_rejected_without_logging_secret() -> None:
    settings = Settings(
        require_verified_policy=True,
        policy_signer_id="release-key",
        policy_signing_key_hex="not-hex",
    )

    with pytest.raises(RuntimeError, match="hexadecimal"):
        verifier_from_settings(settings)
