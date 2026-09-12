from contextlib import asynccontextmanager

from fastapi import FastAPI

from api.router import router
from app.config import Settings
from app.dependencies import get_settings
from app.policy_startup import activate_policy_or_raise, activation_service_from_settings
from policy.activation import PolicyActivationService
from policy.lifecycle import PolicyBundleRegistry
from policy.runtime import ActivePolicyDetector


def create_app(
    settings: Settings | None = None,
    *,
    policy_activation_service: PolicyActivationService | None = None,
) -> FastAPI:
    active_settings = settings or get_settings()
    active_service = policy_activation_service or activation_service_from_settings(active_settings)
    policy_registry = (
        active_service.registry
        if active_service is not None
        else PolicyBundleRegistry()
    )
    @asynccontextmanager
    async def lifespan(_: FastAPI):
        activate_policy_or_raise(active_settings, active_service)
        yield

    application = FastAPI(
        title=active_settings.service_name,
        version="0.1.0",
        lifespan=lifespan,
    )

    from fastapi.middleware.cors import CORSMiddleware
    application.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    from pathlib import Path
    dashboard_out = Path("dashboard/out")
    if dashboard_out.exists() and dashboard_out.is_dir():
        from fastapi.staticfiles import StaticFiles
        application.mount("/dashboard", StaticFiles(directory=str(dashboard_out), html=True), name="dashboard")

    application.include_router(router)
    application.state.policy_detector = ActivePolicyDetector(policy_registry)
    return application

