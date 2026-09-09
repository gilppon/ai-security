from fastapi.testclient import TestClient

from api.health import HealthResponse, health
from app.main import app


def test_health_endpoint_contract() -> None:
    response = health()

    assert response == HealthResponse()
    assert response.model_dump() == {
        "status": "ok",
        "service": "ai-security-control-plane",
    }


def test_health_route_returns_valid_response() -> None:
    response = TestClient(app).get("/v1/health")

    assert response.status_code == 200
    assert response.json() == {
        "status": "ok",
        "service": "ai-security-control-plane",
    }
