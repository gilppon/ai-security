from fastapi.testclient import TestClient

from app.main import app


client = TestClient(app)


def test_public_tool_api_defaults_to_deny_without_verified_identity() -> None:
    response = client.post("/v1/security/tool/authorize", json={
        "tool": "read_file",
        "arguments": {"path": "workspace/readme.md"},
    })

    assert response.status_code == 200
    assert response.json()["decision"]["decision"] == "DENY"
    assert "AGENT_IDENTITY_UNVERIFIED" in response.json()["decision"]["reason_codes"]


def test_public_tool_api_rejects_caller_agent_identity() -> None:
    response = client.post("/v1/security/tool/authorize", json={
        "tool": "status",
        "arguments": {},
        "agent_id": "agent-1",
    })

    assert response.status_code == 422


def test_public_mcp_api_defaults_to_deny_without_verified_identity() -> None:
    response = client.post("/v1/security/mcp/authorize", json={
        "server_id": "project-server",
        "server_version": "1.0.0",
        "tool": "remote_status",
        "arguments": {},
        "requested_scopes": [],
    })

    assert response.status_code == 200
    assert response.json()["decision"]["decision"] == "DENY"
    assert "AGENT_IDENTITY_UNVERIFIED" in response.json()["decision"]["reason_codes"]


def test_public_mcp_api_rejects_caller_agent_identity() -> None:
    response = client.post("/v1/security/mcp/authorize", json={
        "server_id": "project-server",
        "server_version": "1.0.0",
        "tool": "remote_status",
        "arguments": {},
        "requested_scopes": [],
        "agent_id": "agent-1",
    })

    assert response.status_code == 422
