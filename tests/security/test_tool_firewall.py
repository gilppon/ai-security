from ipaddress import ip_address
from pathlib import Path

import pytest
from pydantic import ValidationError

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
from resource_security.filesystem.firewall import FilesystemFirewall
from resource_security.filesystem.models import FilesystemGrant, FilesystemOperation
from resource_security.network.firewall import NetworkFirewall
from resource_security.network.models import NetworkGrant
from telemetry.audit import InMemoryAuditSink, StructuredAuditLogger


class FakeResolver:
    def resolve(self, hostname: str):
        return (ip_address("93.184.216.34"),)


def definition(
    *,
    name: str = "status",
    capability: ToolCapability = ToolCapability.NONE,
    arguments: tuple[ToolArgumentSpec, ...] = (),
    resource_argument: str | None = None,
    filesystem_operation: FilesystemOperation | None = None,
) -> ToolDefinition:
    return ToolDefinition(
        name=name,
        capability=capability,
        arguments=arguments,
        allowed_agents=("agent-1",),
        resource_argument=resource_argument,
        filesystem_operation=filesystem_operation,
    )


def request(tool: str = "status", **arguments: object) -> ToolAuthorizeRequest:
    return ToolAuthorizeRequest.model_validate({"tool": tool, "arguments": arguments})


def test_verified_agent_can_authorize_registered_non_resource_tool() -> None:
    firewall = ToolFirewall(ToolRegistry((definition(),)))

    result = firewall.authorize(request(), verified_agent_id="agent-1")

    assert result.decision.decision is DecisionAction.ALLOW
    assert ReasonCode.TOOL_AUTHORIZED in result.decision.reason_codes


def test_unverified_identity_is_denied_before_tool_grant() -> None:
    firewall = ToolFirewall(ToolRegistry((definition(),)))

    result = firewall.authorize(request())

    assert result.decision.decision is DecisionAction.DENY
    assert ReasonCode.AGENT_IDENTITY_UNVERIFIED in result.decision.reason_codes


def test_malformed_verified_identity_is_treated_as_unverified() -> None:
    firewall = ToolFirewall(ToolRegistry((definition(),)))

    result = firewall.authorize(request(), verified_agent_id="agent\nforged")

    assert result.decision.decision is DecisionAction.DENY
    assert ReasonCode.AGENT_IDENTITY_UNVERIFIED in result.decision.reason_codes


def test_unknown_tool_and_ungranted_agent_are_denied() -> None:
    firewall = ToolFirewall(ToolRegistry((definition(),)))

    unknown = firewall.authorize(request("missing"), verified_agent_id="agent-1")
    wrong_agent = firewall.authorize(request(), verified_agent_id="agent-2")

    assert ReasonCode.TOOL_NOT_REGISTERED in unknown.decision.reason_codes
    assert ReasonCode.TOOL_NOT_ALLOWED in wrong_agent.decision.reason_codes


@pytest.mark.parametrize(
    "arguments",
    [
        {},
        {"count": "1"},
        {"count": 1, "extra": True},
        {"count": 99},
    ],
)
def test_invalid_arguments_are_denied(arguments: dict[str, object]) -> None:
    tool = definition(arguments=(ToolArgumentSpec(
        name="count",
        argument_type=ArgumentType.INTEGER,
        allowed_values=(1, 2),
    ),))
    firewall = ToolFirewall(ToolRegistry((tool,)))

    result = firewall.authorize(
        ToolAuthorizeRequest.model_validate({"tool": "status", "arguments": arguments}),
        verified_agent_id="agent-1",
    )

    assert result.decision.decision is DecisionAction.DENY
    assert ReasonCode.TOOL_ARGUMENT_INVALID in result.decision.reason_codes


def test_filesystem_tool_passes_through_filesystem_firewall(tmp_path: Path) -> None:
    path_spec = ToolArgumentSpec(name="path", argument_type=ArgumentType.STRING)
    tool = definition(
        name="read_file",
        capability=ToolCapability.FILESYSTEM,
        arguments=(path_spec,),
        resource_argument="path",
        filesystem_operation=FilesystemOperation.READ,
    )
    fs = FilesystemFirewall((FilesystemGrant(
        root=tmp_path,
        operations=frozenset({FilesystemOperation.READ}),
    ),))
    firewall = ToolFirewall(ToolRegistry((tool,)), filesystem_firewall=fs)

    result = firewall.authorize(
        request("read_file", path=str(tmp_path / "safe.txt")),
        verified_agent_id="agent-1",
    )

    assert result.decision.decision is DecisionAction.ALLOW
    assert result.resource_authorization_event_id is not None


def test_sensitive_filesystem_denial_propagates_to_tool(tmp_path: Path) -> None:
    path_spec = ToolArgumentSpec(name="path", argument_type=ArgumentType.STRING)
    tool = definition(
        name="read_file",
        capability=ToolCapability.FILESYSTEM,
        arguments=(path_spec,),
        resource_argument="path",
        filesystem_operation=FilesystemOperation.READ,
    )
    fs = FilesystemFirewall((FilesystemGrant(
        root=tmp_path,
        operations=frozenset({FilesystemOperation.READ}),
    ),))
    firewall = ToolFirewall(ToolRegistry((tool,)), filesystem_firewall=fs)

    result = firewall.authorize(
        request("read_file", path=str(tmp_path / ".env")),
        verified_agent_id="agent-1",
    )

    assert result.decision.decision is DecisionAction.DENY
    assert ReasonCode.RESOURCE_AUTHORIZATION_DENIED in result.decision.reason_codes
    assert ReasonCode.SENSITIVE_PATH in result.decision.reason_codes


def test_network_tool_passes_through_network_firewall() -> None:
    url_spec = ToolArgumentSpec(name="url", argument_type=ArgumentType.STRING)
    tool = definition(
        name="fetch_url",
        capability=ToolCapability.NETWORK,
        arguments=(url_spec,),
        resource_argument="url",
    )
    network = NetworkFirewall((NetworkGrant("example.com"),), resolver=FakeResolver())
    firewall = ToolFirewall(ToolRegistry((tool,)), network_firewall=network)

    result = firewall.authorize(
        request("fetch_url", url="https://example.com"),
        verified_agent_id="agent-1",
    )

    assert result.decision.decision is DecisionAction.ALLOW
    assert result.resource_authorization_event_id is not None


def test_missing_resource_firewall_defaults_to_deny() -> None:
    tool = definition(
        name="fetch_url",
        capability=ToolCapability.NETWORK,
        arguments=(ToolArgumentSpec(name="url", argument_type=ArgumentType.STRING),),
        resource_argument="url",
    )
    firewall = ToolFirewall(ToolRegistry((tool,)))

    result = firewall.authorize(
        request("fetch_url", url="https://example.com"),
        verified_agent_id="agent-1",
    )

    assert result.decision.decision is DecisionAction.DENY
    assert ReasonCode.RESOURCE_FIREWALL_UNAVAILABLE in result.decision.reason_codes
    assert result.resource_authorization_event_id is None


def test_argument_values_are_not_audited() -> None:
    sink = InMemoryAuditSink()
    tool = definition(arguments=(ToolArgumentSpec(
        name="query",
        argument_type=ArgumentType.STRING,
    ),))
    firewall = ToolFirewall(
        ToolRegistry((tool,)),
        audit_logger=StructuredAuditLogger(sink),
    )
    raw_value = "private argument value"

    firewall.authorize(request(query=raw_value), verified_agent_id="agent-1")

    assert raw_value not in sink.records[0]


def test_registry_and_definition_reject_ambiguous_grants() -> None:
    tool = definition()
    with pytest.raises(ValueError, match="already registered"):
        ToolRegistry((tool, tool))
    with pytest.raises(ValidationError, match="explicit agent"):
        ToolDefinition(
            name="unsafe",
            capability=ToolCapability.NONE,
            allowed_agents=("*",),
        )


def test_tool_request_limits_argument_count() -> None:
    with pytest.raises(ValidationError):
        ToolAuthorizeRequest(
            tool="status",
            arguments={f"arg_{index}": index for index in range(65)},
        )
