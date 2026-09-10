from functools import lru_cache
from typing import Annotated

from fastapi import APIRouter, Depends, Request

from agent_security.tools.firewall import ToolFirewall
from agent_security.tools.schemas import ToolAuthorizationResult, ToolAuthorizeRequest
from policy.runtime import ActivePolicyDetector


@lru_cache
def _tool_firewall(policy_detector: ActivePolicyDetector) -> ToolFirewall:
    return ToolFirewall(policy_detector=policy_detector)


def get_tool_firewall(request: Request) -> ToolFirewall:
    return _tool_firewall(request.app.state.policy_detector)


ToolFirewallDep = Annotated[ToolFirewall, Depends(get_tool_firewall)]
router = APIRouter(prefix="/security/tool", tags=["tool-security"])


@router.post("/authorize")
def authorize_tool(request: ToolAuthorizeRequest, firewall: ToolFirewallDep) -> ToolAuthorizationResult:
    return firewall.authorize(request)
