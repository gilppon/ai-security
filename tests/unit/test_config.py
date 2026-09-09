import pytest
from pydantic import ValidationError

from app.config import Settings


def test_settings_load_allowlisted_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AI_SECURITY_ENVIRONMENT", "production")

    assert Settings.from_environment().environment == "production"


def test_settings_reject_unknown_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AI_SECURITY_ENVIRONMENT", "unsafe")

    with pytest.raises(ValidationError):
        Settings.from_environment()
