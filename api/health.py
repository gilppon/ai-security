from typing import Literal

from fastapi import APIRouter
from pydantic import BaseModel, ConfigDict


class HealthResponse(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    status: Literal["ok"] = "ok"
    service: str = "ai-security-control-plane"


router = APIRouter()


@router.get("/health")
def health() -> HealthResponse:
    return HealthResponse()

