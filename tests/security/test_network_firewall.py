from ipaddress import ip_address

import pytest

from core.decisions.actions import DecisionAction
from core.decisions.reasons import ReasonCode
from resource_security.network.firewall import NetworkFirewall
from resource_security.network.models import NetworkAuthorizationRequest, NetworkGrant
from telemetry.audit import InMemoryAuditSink, StructuredAuditLogger


class FakeResolver:
    def __init__(self, records: dict[str, tuple[str, ...]]) -> None:
        self.records = records
        self.calls: list[str] = []

    def resolve(self, hostname: str):
        self.calls.append(hostname)
        return tuple(ip_address(value) for value in self.records.get(hostname, ()))


def firewall(
    records: dict[str, tuple[str, ...]],
    *hosts: str,
) -> tuple[NetworkFirewall, FakeResolver, InMemoryAuditSink]:
    resolver = FakeResolver(records)
    sink = InMemoryAuditSink()
    grants = tuple(NetworkGrant(host) for host in hosts)
    return NetworkFirewall(
        grants,
        resolver=resolver,
        audit_logger=StructuredAuditLogger(sink),
    ), resolver, sink


def authorize(firewall: NetworkFirewall, url: str):
    return firewall.authorize(NetworkAuthorizationRequest(url=url))


def test_public_https_is_allowed_with_pinned_addresses() -> None:
    guard, resolver, _ = firewall({"example.com": ("93.184.216.34",)}, "example.com")

    result = authorize(guard, "https://example.com/data")

    assert result.decision.decision is DecisionAction.ALLOW
    assert result.resolved_addresses == ("93.184.216.34",)
    assert result.redirect_reauthorization_required is True
    assert resolver.calls == ["example.com"]
    assert ReasonCode.NETWORK_AUTHORIZED in result.decision.reason_codes


def test_authorized_resource_is_bound_to_resolved_address() -> None:
    guard, _, _ = firewall({"example.com": ("93.184.216.34",)}, "example.com")

    result = authorize(guard, "https://example.com/data")

    assert result.decision.decision is DecisionAction.ALLOW
    assert result.normalized_resource == "https://93.184.216.34:443"


def test_http_scheme_is_denied_before_dns() -> None:
    guard, resolver, _ = firewall({"example.com": ("93.184.216.34",)}, "example.com")

    result = authorize(guard, "http://example.com")

    assert result.decision.decision is DecisionAction.DENY
    assert ReasonCode.NETWORK_SCHEME_DENIED in result.decision.reason_codes
    assert resolver.calls == []


def test_url_credentials_are_denied() -> None:
    guard, resolver, _ = firewall({"example.com": ("93.184.216.34",)}, "example.com")

    result = authorize(guard, "https://user:password@example.com")

    assert result.decision.decision is DecisionAction.DENY
    assert ReasonCode.NETWORK_CREDENTIALS_DENIED in result.decision.reason_codes
    assert resolver.calls == []


def test_non_allowlisted_host_is_denied_without_dns() -> None:
    guard, resolver, _ = firewall({"evil.example": ("93.184.216.34",)}, "example.com")

    result = authorize(guard, "https://evil.example")

    assert result.decision.decision is DecisionAction.DENY
    assert ReasonCode.NETWORK_HOST_DENIED in result.decision.reason_codes
    assert resolver.calls == []


@pytest.mark.parametrize(
    ("hostname", "address"),
    [
        ("localhost", "127.0.0.1"),
        ("private.test", "10.0.0.8"),
        ("rfc1918.test", "192.168.1.9"),
        ("linklocal.test", "169.254.10.2"),
        ("loopback6.test", "::1"),
        ("private6.test", "fd00::1"),
        ("linklocal6.test", "fe80::1"),
    ],
)
def test_non_public_destinations_are_denied(hostname: str, address: str) -> None:
    guard, _, _ = firewall({hostname: (address,)}, hostname)

    result = authorize(guard, f"https://{hostname}")

    assert result.decision.decision is DecisionAction.DENY
    assert ReasonCode.PRIVATE_NETWORK_DESTINATION in result.decision.reason_codes


def test_cloud_metadata_endpoint_has_specific_denial() -> None:
    guard, _, _ = firewall({}, "169.254.169.254")

    result = authorize(guard, "https://169.254.169.254/latest/meta-data")

    assert result.decision.decision is DecisionAction.DENY
    assert ReasonCode.METADATA_ENDPOINT in result.decision.reason_codes


def test_mixed_public_private_dns_answer_is_denied() -> None:
    guard, _, _ = firewall(
        {"rebind.test": ("93.184.216.34", "127.0.0.1")},
        "rebind.test",
    )

    result = authorize(guard, "https://rebind.test")

    assert result.decision.decision is DecisionAction.DENY
    assert result.resolved_addresses == ()


def test_scoped_wildcard_does_not_match_apex_or_suffix_confusion() -> None:
    records = {
        "api.example.com": ("93.184.216.34",),
        "example.com": ("93.184.216.34",),
        "evil-example.com": ("93.184.216.34",),
    }
    guard, _, _ = firewall(records, "*.example.com")

    allowed = authorize(guard, "https://api.example.com")
    apex = authorize(guard, "https://example.com")
    confused = authorize(guard, "https://evil-example.com")

    assert allowed.decision.decision is DecisionAction.ALLOW
    assert apex.decision.decision is DecisionAction.DENY
    assert confused.decision.decision is DecisionAction.DENY


def test_redirect_target_is_fully_reauthorized() -> None:
    guard, _, _ = firewall(
        {
            "example.com": ("93.184.216.34",),
            "internal.test": ("127.0.0.1",),
        },
        "example.com",
        "internal.test",
    )

    initial = authorize(guard, "https://example.com")
    redirect = guard.authorize_redirect("https://internal.test")

    assert initial.decision.decision is DecisionAction.ALLOW
    assert redirect.decision.decision is DecisionAction.DENY


def test_empty_dns_result_is_denied() -> None:
    guard, _, _ = firewall({}, "missing.test")

    result = authorize(guard, "https://missing.test")

    assert result.decision.decision is DecisionAction.DENY
    assert ReasonCode.DNS_RESOLUTION_FAILED in result.decision.reason_codes


def test_raw_url_is_not_written_to_audit() -> None:
    guard, _, sink = firewall({"example.com": ("93.184.216.34",)}, "example.com")
    raw_url = "https://example.com/path?private=value"

    authorize(guard, raw_url)

    assert raw_url not in sink.records[0]


def test_scoped_wildcard_does_not_match_parent_or_lookalike() -> None:
    guard, _, _ = firewall(
        {
            "api.example.com": ("93.184.216.34",),
            "example.com": ("93.184.216.34",),
            "evil-example.com": ("93.184.216.34",),
        },
        "*.example.com",
    )

    child = authorize(guard, "https://api.example.com")
    parent = authorize(guard, "https://example.com")
    lookalike = authorize(guard, "https://evil-example.com")

    assert child.decision.decision is DecisionAction.ALLOW
    assert parent.decision.decision is DecisionAction.DENY
    assert lookalike.decision.decision is DecisionAction.DENY


def test_dns_addresses_are_deduplicated_and_sorted() -> None:
    guard, _, _ = firewall(
        {"example.com": ("93.184.216.35", "93.184.216.34", "93.184.216.35")},
        "example.com",
    )

    result = authorize(guard, "https://example.com")

    assert result.resolved_addresses == ("93.184.216.34", "93.184.216.35")


def test_url_whitespace_is_denied() -> None:
    guard, resolver, _ = firewall({"example.com": ("93.184.216.34",)}, "example.com")

    result = authorize(guard, " https://example.com")

    assert result.decision.decision is DecisionAction.DENY
    assert result.decision.reason_codes == (ReasonCode.INVALID_NETWORK_DESTINATION,)
    assert resolver.calls == []


def test_overbroad_wildcard_grant_is_rejected() -> None:
    with pytest.raises(ValueError, match="scoped"):
        NetworkGrant("*.com")
