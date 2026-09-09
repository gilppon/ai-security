from fastapi.testclient import TestClient

from api.runtime import get_runtime_monitor, get_verified_runtime_agent_id
from app.main import app
from runtime.behavior.profiles import BehaviorProfile
from runtime.models import RuntimeActivity
from runtime.monitor import RuntimeMonitor


client = TestClient(app)


def test_public_runtime_event_defaults_to_deny() -> None:
    response = client.post("/v1/security/events", json={
        "session_id": "session-1",
        "activity": "tool_call",
        "outcome": "allowed",
        "target_fingerprint": "a" * 16,
    })

    assert response.status_code == 200
    body = response.json()
    assert body["decision"]["decision"] == "DENY"
    assert "RUNTIME_IDENTITY_UNVERIFIED" in body["decision"]["reason_codes"]
    assert body["session_event_count"] == 0


def test_public_session_inspection_defaults_to_deny_without_summary() -> None:
    response = client.get("/v1/security/sessions/session-1")

    assert response.status_code == 200
    body = response.json()
    assert body["decision"]["decision"] == "DENY"
    assert body["summary"] is None


def test_runtime_event_cannot_assert_identity_trust_or_risk() -> None:
    response = client.post("/v1/security/events", json={
        "session_id": "session-1",
        "activity": "prompt",
        "outcome": "allowed",
        "agent_id": "agent-1",
        "trust_level": "trusted",
        "risk_score": 0,
    })

    assert response.status_code == 422


def test_verified_runtime_api_records_and_inspects_session() -> None:
    monitor = RuntimeMonitor((BehaviorProfile(
        agent_id="agent-1",
        allowed_activities=frozenset(RuntimeActivity),
    ),))
    app.dependency_overrides[get_runtime_monitor] = lambda: monitor
    app.dependency_overrides[get_verified_runtime_agent_id] = lambda: "agent-1"

    try:
        observed = client.post("/v1/security/events", json={
            "session_id": "session-authenticated",
            "activity": "prompt",
            "outcome": "allowed",
        })
        inspected = client.get(
            "/v1/security/sessions/session-authenticated"
        )
    finally:
        app.dependency_overrides.pop(get_runtime_monitor, None)
        app.dependency_overrides.pop(get_verified_runtime_agent_id, None)

    assert observed.status_code == 200
    assert observed.json()["decision"]["decision"] == "ALLOW"
    assert inspected.status_code == 200
    assert inspected.json()["summary"]["event_count"] == 1
