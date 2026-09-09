from functools import lru_cache
from typing import Annotated

from fastapi import APIRouter, Depends

from agent_security.mcp.gateway import MCPGateway
from agent_security.mcp.models import MCPAuthorizationResult, MCPAuthorizeRequest
from api.tool import get_tool_firewall


@lru_cache
def get_mcp_gateway() -> MCPGateway:
    return MCPGateway(tool_firewall=get_tool_firewall())


MCPGatewayDep = Annotated[MCPGateway, Depends(get_mcp_gateway)]
router = APIRouter(prefix="/security/mcp", tags=["mcp-security"])


@router.post("/authorize")
def authorize_mcp(request: MCPAuthorizeRequest, gateway: MCPGatewayDep) -> MCPAuthorizationResult:
    return gateway.authorize(request)
