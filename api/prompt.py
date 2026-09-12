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


from api.events import broadcast_security_event

@router.post("/scan")
def scan_prompt(request: PromptScanRequest, firewall: PromptFirewallDep) -> PromptScanResult:
    result = firewall.scan(request)
    broadcast_security_event({
        "event_id": result.event_id,
        "event_type": "prompt.scan",
        "decision": result.decision.decision.value,
        "risk_score": result.decision.risk_score,
        "reason_codes": [c.value for c in result.decision.reason_codes],
        "findings": [f.model_dump(mode="json") for f in result.findings],
        "length": result.input_length,
        "fingerprint": result.prompt_fingerprint,
    })
    return result
