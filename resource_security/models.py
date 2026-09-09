from pydantic import BaseModel, ConfigDict

from core.decisions.models import SecurityDecision


class ResourceAuthorizationResult(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    event_id: str
    decision: SecurityDecision
    normalized_resource: str | None = None
    resolved_addresses: tuple[str, ...] = ()
    redirect_reauthorization_required: bool = False

