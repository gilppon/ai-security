from ipaddress import ip_address

import pytest
from pydantic import ValidationError

from core.decisions.actions import DecisionAction
from core.decisions.reasons import ReasonCode
from resource_security.api.firewall import APIFirewall
from resource_security.api.models import APIAuthorizationRequest, APIEndpointGrant, HTTPMethod
from resource_security.database.firewall import DatabaseFirewall
from resource_security.database.models import (
    DatabaseAuthorizationRequest,
    DatabaseGrant,
    DatabaseOperation,
    DatabaseTableGrant,
)
from resource_security.network.firewall import NetworkFirewall
from resource_security.network.models import NetworkGrant


class PublicResolver:
    def resolve(self, hostname: str):
        return (ip_address("93.184.216.34"),)


class PrivateResolver:
    def resolve(self, hostname: str):
        return (ip_address("127.0.0.1"),)


def database_firewall() -> DatabaseFirewall:
    return DatabaseFirewall((DatabaseGrant(
        database_id="analytics",
        allowed_agents=frozenset({"agent-1"}),
        tables=(DatabaseTableGrant(
            table="events",
            operations=frozenset({DatabaseOperation.SELECT}),
            columns=frozenset({"id", "kind"}),
            predicate_fields=frozenset({"id"}),
        ),),
    ),))


def test_database_structured_query_is_least_privilege() -> None:
    firewall = database_firewall()
    allowed = firewall.authorize(DatabaseAuthorizationRequest(
        database_id="analytics",
        operation=DatabaseOperation.SELECT,
        table="events",
        columns=("id", "kind"),
        predicate_fields=("id",),
    ), verified_agent_id="agent-1")
    denied = firewall.authorize(DatabaseAuthorizationRequest(
        database_id="analytics",
        operation=DatabaseOperation.DELETE,
        table="events",
        columns=("id",),
    ), verified_agent_id="agent-1")

    assert allowed.decision.decision is DecisionAction.ALLOW
    assert ReasonCode.DATABASE_AUTHORIZED in allowed.decision.reason_codes
    assert ReasonCode.DATABASE_OPERATION_DENIED in denied.decision.reason_codes


def test_database_rejects_unverified_identity_columns_and_raw_sql() -> None:
    firewall = database_firewall()
    request = DatabaseAuthorizationRequest(
        database_id="analytics",
        operation=DatabaseOperation.SELECT,
        table="events",
        columns=("secret",),
    )

    unverified = firewall.authorize(request)
    denied_column = firewall.authorize(request, verified_agent_id="agent-1")

    assert ReasonCode.DATABASE_IDENTITY_UNVERIFIED in unverified.decision.reason_codes
    assert ReasonCode.DATABASE_COLUMN_DENIED in denied_column.decision.reason_codes
    with pytest.raises(ValidationError):
        DatabaseAuthorizationRequest.model_validate({
            "database_id": "analytics",
            "operation": "select",
            "table": "events",
            "columns": ["id"],
            "sql": "SELECT * FROM events",
        })


def api_firewall() -> APIFirewall:
    network = NetworkFirewall((NetworkGrant("api.example.com"),), resolver=PublicResolver())
    return APIFirewall((APIEndpointGrant(
        api_id="events.read",
        method=HTTPMethod.GET,
        origin="https://api.example.com",
        path="/v1/events",
        allowed_agents=frozenset({"agent-1"}),
        allowed_query_parameters=frozenset({"limit"}),
    ),), network_firewall=network)


def test_api_requires_exact_endpoint_and_network_authorization() -> None:
    firewall = api_firewall()
    allowed = firewall.authorize(APIAuthorizationRequest(
        api_id="events.read",
        method=HTTPMethod.GET,
        url="https://api.example.com/v1/events?limit=10",
    ), verified_agent_id="agent-1")
    path_denied = firewall.authorize(APIAuthorizationRequest(
        api_id="events.read",
        method=HTTPMethod.GET,
        url="https://api.example.com/v1/admin",
    ), verified_agent_id="agent-1")
    query_denied = firewall.authorize(APIAuthorizationRequest(
        api_id="events.read",
        method=HTTPMethod.GET,
        url="https://api.example.com/v1/events?token=secret",
    ), verified_agent_id="agent-1")

    assert allowed.decision.decision is DecisionAction.ALLOW
    assert allowed.resolved_addresses == ("93.184.216.34",)
    assert ReasonCode.API_PATH_DENIED in path_denied.decision.reason_codes
    assert ReasonCode.API_ARGUMENT_DENIED in query_denied.decision.reason_codes


def test_api_defaults_to_deny_without_identity_or_network_firewall() -> None:
    request = APIAuthorizationRequest(
        api_id="events.read",
        method=HTTPMethod.GET,
        url="https://api.example.com/v1/events",
    )
    unverified = api_firewall().authorize(request)
    missing_network = APIFirewall((APIEndpointGrant(
        api_id="events.read",
        method=HTTPMethod.GET,
        origin="https://api.example.com",
        path="/v1/events",
        allowed_agents=frozenset({"agent-1"}),
    ),)).authorize(request, verified_agent_id="agent-1")

    assert ReasonCode.API_IDENTITY_UNVERIFIED in unverified.decision.reason_codes
    assert ReasonCode.RESOURCE_FIREWALL_UNAVAILABLE in missing_network.decision.reason_codes


def test_api_propagates_network_firewall_reason_codes() -> None:
    network = NetworkFirewall((NetworkGrant("api.example.com"),), resolver=PrivateResolver())
    firewall = APIFirewall((APIEndpointGrant(
        api_id="events.read",
        method=HTTPMethod.GET,
        origin="https://api.example.com",
        path="/v1/events",
        allowed_agents=frozenset({"agent-1"}),
    ),), network_firewall=network)

    result = firewall.authorize(APIAuthorizationRequest(
        api_id="events.read",
        method=HTTPMethod.GET,
        url="https://api.example.com/v1/events",
    ), verified_agent_id="agent-1")

    assert ReasonCode.API_NETWORK_DENIED in result.decision.reason_codes
    assert ReasonCode.PRIVATE_NETWORK_DESTINATION in result.decision.reason_codes
