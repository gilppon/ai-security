from functools import lru_cache
from typing import Annotated

from fastapi import APIRouter, Depends

from input_security.prompt.firewall import PromptFirewall
from input_security.prompt.models import PromptScanRequest, PromptScanResult


@lru_cache
def get_prompt_firewall() -> PromptFirewall:
    return PromptFirewall()


PromptFirewallDep = Annotated[PromptFirewall, Depends(get_prompt_firewall)]

router = APIRouter(prefix="/security/prompt", tags=["prompt-security"])


@router.post("/scan")
def scan_prompt(request: PromptScanRequest, firewall: PromptFirewallDep) -> PromptScanResult:
    return firewall.scan(request)

