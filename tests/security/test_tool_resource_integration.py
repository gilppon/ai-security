from ipaddress import ip_address
from pathlib import Path
import sys

from core.decisions.actions import DecisionAction
from core.decisions.reasons import ReasonCode
from agent_security.tools.firewall import ToolFirewall
from agent_security.tools.registry import ToolRegistry
from agent_security.tools.schemas import (
    ArgumentType,
    ToolArgumentSpec,
    ToolAuthorizeRequest,
    ToolCapability,
    ToolDefinition,
)
from resource_security.api.firewall import APIFirewall
from resource_security.api.models import APIEndpointGrant, HTTPMethod
from resource_security.database.firewall import DatabaseFirewall
from resource_security.database.models import DatabaseGrant, DatabaseOperation, DatabaseTableGrant
from resource_security.filesystem.firewall import FilesystemFirewall
from resource_security.filesystem.models import FilesystemGrant, FilesystemOperation
from resource_security.network.firewall import NetworkFirewall
from resource_security.network.models import NetworkGrant
from resource_security.process.firewall import ProcessFirewall
from resource_security.process.models import ProcessGrant


class PublicResolver:
    def resolve(self, hostname: str):
        return (ip_address("93.184.216.34"),)


def structured_tool(name: str, capability: ToolCapability) -> ToolDefinition:
    return ToolDefinition(
        name=name,
        capability=capability,
        arguments=(ToolArgumentSpec(name="request", argument_type=ArgumentType.OBJECT),),
        allowed_agents=("agent-1",),
        resource_argument="request",
    )


def test_process_capability_can_only_be_minted_through_tool_firewall(tmp_path: Path) -> None:
    script = tmp_path / "safe.py"
    script.write_text("print('ok')", encoding="utf-8")
    filesystem = FilesystemFirewall((FilesystemGrant(
        root=tmp_path,
        operations=frozenset({FilesystemOperation.LIST, FilesystemOperation.READ}),
    ),))
    process = ProcessFirewall((ProcessGrant(
        executable=Path(sys.executable),
        argument_prefix=(),
        working_roots=(tmp_path,),
        path_argument_indices=(1,),
        max_timeout_seconds=2,
    ),), filesystem_firewall=filesystem)
    firewall = ToolFirewall(
        ToolRegistry((structured_tool("run_test", ToolCapability.PROCESS),)),
        process_firewall=process,
    )
    request = ToolAuthorizeRequest(tool="run_test", arguments={"request": {
        "argv": [sys.executable, str(script)],
        "working_directory": str(tmp_path),
        "timeout_seconds": 1,
    }})

    denied = firewall.authorize(request)
    allowed = firewall.authorize(request, verified_agent_id="agent-1")

    assert denied.process_capability is None
    assert allowed.decision.decision is DecisionAction.ALLOW
    assert allowed.process_capability is not None


def test_database_tool_propagates_structured_authorization() -> None:
    database = DatabaseFirewall((DatabaseGrant(
        database_id="analytics",
        allowed_agents=frozenset({"agent-1"}),
        tables=(DatabaseTableGrant(
            table="events",
            operations=frozenset({DatabaseOperation.SELECT}),
            columns=frozenset({"id"}),
        ),),
    ),))
    firewall = ToolFirewall(
        ToolRegistry((structured_tool("read_events", ToolCapability.DATABASE),)),
        database_firewall=database,
    )
    result = firewall.authorize(ToolAuthorizeRequest(tool="read_events", arguments={"request": {
        "database_id": "analytics",
        "operation": "select",
        "table": "events",
        "columns": ["id"],
    }}), verified_agent_id="agent-1")

    assert result.decision.decision is DecisionAction.ALLOW
    assert result.resource_authorization_event_id is not None


def test_api_tool_propagates_network_denial() -> None:
    network = NetworkFirewall((NetworkGrant("api.example.com"),), resolver=PublicResolver())
    api = APIFirewall((APIEndpointGrant(
        api_id="events.read",
        method=HTTPMethod.GET,
        origin="https://api.example.com",
        path="/v1/events",
        allowed_agents=frozenset({"agent-1"}),
    ),), network_firewall=network)
    firewall = ToolFirewall(
        ToolRegistry((structured_tool("fetch_events", ToolCapability.API),)),
        api_firewall=api,
    )
    result = firewall.authorize(ToolAuthorizeRequest(tool="fetch_events", arguments={"request": {
        "api_id": "events.read",
        "method": "GET",
        "url": "https://api.example.com/v1/admin",
    }}), verified_agent_id="agent-1")

    assert result.decision.decision is DecisionAction.DENY
    assert ReasonCode.RESOURCE_AUTHORIZATION_DENIED in result.decision.reason_codes
    assert ReasonCode.API_PATH_DENIED in result.decision.reason_codes
