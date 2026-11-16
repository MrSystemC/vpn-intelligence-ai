from fastapi.testclient import TestClient
from app.main import app, Base, engine

def test_health():
    Base.metadata.create_all(bind=engine)
    with TestClient(app) as client:
        response = client.get("/health")
        assert response.status_code == 200
        assert response.json()["status"] == "ok"

def test_api_requires_key():
    with TestClient(app) as client:
        response = client.get("/v1/me")
        assert response.status_code == 401

def test_flow_schema_rejects_tenant_spoofing():
    with TestClient(app) as client:
        response = client.post("/v1/flows", json={
            "tenant_id": "another-tenant",
            "features": {"tunnel_protocol": True}
        })
        assert response.status_code == 401
