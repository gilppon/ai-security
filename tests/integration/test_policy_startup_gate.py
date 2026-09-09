import asyncio
import pytest

from app.bootstrap import create_app
from app.config import Settings


def test_fastapi_startup_gate_denies_missing_activation_service() -> None:
    app = create_app(
        Settings(
            require_verified_policy=True,
            policy_signer_id="release-key",
            policy_signing_key_hex="00" * 32,
        )
    )
    async def start() -> None:
        async with app.router.lifespan_context(app):
            pass

    with pytest.raises(RuntimeError, match="activation service"):
        asyncio.run(start())
