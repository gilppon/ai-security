from contextlib import asynccontextmanager

from fastapi import FastAPI

from api.router import router
from app.config import Settings
from app.dependencies import get_settings
from app.policy_startup import activate_policy_or_raise
from policy.activation import PolicyActivationService


def create_app(
    settings: Settings | None = None,
    *,
    policy_activation_service: PolicyActivationService | None = None,
) -> FastAPI:
    active_settings = settings or get_settings()
    @asynccontextmanager
    async def lifespan(_: FastAPI):
        activate_policy_or_raise(active_settings, policy_activation_service)
        yield

    application = FastAPI(
        title=active_settings.service_name,
        version="0.1.0",
        lifespan=lifespan,
    )

    application.include_router(router)
    return application
