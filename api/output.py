from functools import lru_cache
from typing import Annotated

from fastapi import APIRouter, Depends, Request

from output_security.guard import OutputGuard
from output_security.models import OutputScanRequest, OutputScanResult
from policy.runtime import ActivePolicyDetector


@lru_cache
def _output_guard(policy_detector: ActivePolicyDetector) -> OutputGuard:
    return OutputGuard(policy_detector=policy_detector)


def get_output_guard(request: Request) -> OutputGuard:
    return _output_guard(request.app.state.policy_detector)


OutputGuardDep = Annotated[OutputGuard, Depends(get_output_guard)]

router = APIRouter(prefix="/security/output", tags=["output-security"])


@router.post("/scan")
def scan_output(request: OutputScanRequest, guard: OutputGuardDep) -> OutputScanResult:
    return guard.scan(request)
