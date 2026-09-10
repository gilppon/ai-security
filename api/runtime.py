from functools import lru_cache
from typing import Annotated

from fastapi import APIRouter, Depends, Request

from runtime.models import (
    RuntimeEventRequest,
    RuntimeObservationResult,
    SessionInspectionResult,
)
from runtime.monitor import RuntimeMonitor
from policy.runtime import ActivePolicyDetector


@lru_cache
def _runtime_monitor(policy_detector: ActivePolicyDetector) -> RuntimeMonitor:
    return RuntimeMonitor(policy_detector=policy_detector)


def get_runtime_monitor(request: Request) -> RuntimeMonitor:
    return _runtime_monitor(request.app.state.policy_detector)


def get_verified_runtime_agent_id() -> str | None:
    return None


RuntimeMonitorDep = Annotated[RuntimeMonitor, Depends(get_runtime_monitor)]
VerifiedRuntimeAgentDep = Annotated[
    str | None,
    Depends(get_verified_runtime_agent_id),
]

router = APIRouter(prefix="/security", tags=["runtime-security"])


@router.post("/events")
def observe_runtime_event(
    request: RuntimeEventRequest,
    monitor: RuntimeMonitorDep,
    verified_agent_id: VerifiedRuntimeAgentDep,
) -> RuntimeObservationResult:
    return monitor.observe(request, verified_agent_id=verified_agent_id)


@router.get("/sessions/{session_id}")
def inspect_runtime_session(
    session_id: str,
    monitor: RuntimeMonitorDep,
    verified_agent_id: VerifiedRuntimeAgentDep,
) -> SessionInspectionResult:
    return monitor.inspect_session(session_id, verified_agent_id=verified_agent_id)
