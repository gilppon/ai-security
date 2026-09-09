from functools import lru_cache
from typing import Annotated

from fastapi import APIRouter, Depends

from agent_security.tools.firewall import ToolFirewall
from agent_security.tools.schemas import ToolAuthorizationResult, ToolAuthorizeRequest


@lru_cache
def get_tool_firewall() -> ToolFirewall:
    return ToolFirewall()


ToolFirewallDep = Annotated[ToolFirewall, Depends(get_tool_firewall)]
router = APIRouter(prefix="/security/tool", tags=["tool-security"])


@router.post("/authorize")
def authorize_tool(request: ToolAuthorizeRequest, firewall: ToolFirewallDep) -> ToolAuthorizationResult:
    return firewall.authorize(request)

