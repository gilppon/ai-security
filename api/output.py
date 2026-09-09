from functools import lru_cache
from typing import Annotated

from fastapi import APIRouter, Depends

from output_security.guard import OutputGuard
from output_security.models import OutputScanRequest, OutputScanResult


@lru_cache
def get_output_guard() -> OutputGuard:
    return OutputGuard()


OutputGuardDep = Annotated[OutputGuard, Depends(get_output_guard)]

router = APIRouter(prefix="/security/output", tags=["output-security"])


@router.post("/scan")
def scan_output(request: OutputScanRequest, guard: OutputGuardDep) -> OutputScanResult:
    return guard.scan(request)
