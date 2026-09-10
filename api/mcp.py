from functools import lru_cache
from typing import Annotated

from fastapi import APIRouter, Depends, Request

from agent_security.mcp.gateway import MCPGateway
from agent_security.mcp.models import MCPAuthorizationResult, MCPAuthorizeRequest
from agent_security.tools.firewall import ToolFirewall
from policy.runtime import ActivePolicyDetector


@lru_cache
def _mcp_gateway(policy_detector: ActivePolicyDetector) -> MCPGateway:
    return MCPGateway(
        tool_firewall=ToolFirewall(policy_detector=policy_detector),
        policy_detector=policy_detector,
    )


def get_mcp_gateway(request: Request) -> MCPGateway:
    return _mcp_gateway(request.app.state.policy_detector)


MCPGatewayDep = Annotated[MCPGateway, Depends(get_mcp_gateway)]
router = APIRouter(prefix="/security/mcp", tags=["mcp-security"])


@router.post("/authorize")
def authorize_mcp(request: MCPAuthorizeRequest, gateway: MCPGatewayDep) -> MCPAuthorizationResult:
    return gateway.authorize(request)
