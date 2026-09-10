from functools import lru_cache
from typing import Annotated

from fastapi import APIRouter, Depends, Request

from input_security.prompt.firewall import PromptFirewall
from input_security.prompt.models import PromptScanRequest, PromptScanResult
from policy.runtime import ActivePolicyDetector


def get_prompt_firewall(request: Request) -> PromptFirewall:
    return _prompt_firewall(request.app.state.policy_detector)


@lru_cache
def _prompt_firewall(policy_detector: ActivePolicyDetector) -> PromptFirewall:
    return PromptFirewall(policy_detector=policy_detector)


PromptFirewallDep = Annotated[PromptFirewall, Depends(get_prompt_firewall)]

router = APIRouter(prefix="/security/prompt", tags=["prompt-security"])


@router.post("/scan")
def scan_prompt(request: PromptScanRequest, firewall: PromptFirewallDep) -> PromptScanResult:
    return firewall.scan(request)
