import pytest

from core.decisions.reasons import ReasonCode
from agent_security.mcp.result_capabilities import MCPResultCapabilityStore


def issue(store: MCPResultCapabilityStore) -> str:
    return store.issue(
        authorization_event_id="evt_authorize",
        agent_id="agent-1",
        server_id="project-server",
        tool="remote_status",
        session_id="session-1",
    )


def test_result_capability_binds_identity_and_is_single_use() -> None:
    store = MCPResultCapabilityStore()
    capability = issue(store)

    mismatch, mismatch_reason = store.consume(
        capability,
        agent_id="agent-2",
        server_id="project-server",
    )
    grant, reason = store.consume(
        capability,
        agent_id="agent-1",
        server_id="project-server",
    )
    replay, replay_reason = store.consume(
        capability,
        agent_id="agent-1",
        server_id="project-server",
    )

    assert mismatch is None
    assert mismatch_reason is ReasonCode.MCP_RESULT_IDENTITY_MISMATCH
    assert grant is not None and reason is None
    assert replay is None
    assert replay_reason is ReasonCode.MCP_RESULT_CAPABILITY_REPLAYED


def test_result_capability_expiry_and_capacity_fail_closed() -> None:
    now = [1.0]
    store = MCPResultCapabilityStore(
        ttl_seconds=1,
        max_active=1,
        clock=lambda: now[0],
    )
    capability = issue(store)

    try:
        issue(store)
    except RuntimeError as error:
        assert "capacity" in str(error)
    else:
        raise AssertionError("capacity exhaustion must fail")

    now[0] = 3.0
    grant, reason = store.consume(
        capability,
        agent_id="agent-1",
        server_id="project-server",
    )

    assert grant is None
    assert reason is ReasonCode.MCP_RESULT_CAPABILITY_EXPIRED


def test_result_capability_rejects_invalid_bound_identity() -> None:
    store = MCPResultCapabilityStore()

    with pytest.raises(ValueError, match="verified identities"):
        store.issue(
            authorization_event_id="evt_authorize",
            agent_id="",
            server_id="project-server",
            tool="remote_status",
            session_id=None,
        )
