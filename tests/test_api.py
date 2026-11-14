import time
import pytest
from fastapi.testclient import TestClient
from sentinel.main import app


@pytest.fixture
def client():
    return TestClient(app)


def test_health_and_readiness(client):
    r = client.get("/health")
    assert r.status_code == 200
    data = r.json()
    assert data["service"] == "sentinel"
    assert data["status"] == "ok"
    assert data["layers"] == 7

    r_ready = client.get("/ready")
    assert r_ready.status_code == 200
    ready_data = r_ready.json()
    assert ready_data["status"] == "ready"
    assert ready_data["checks"]["crypto_vault"] == "ok"
    assert ready_data["checks"]["policy"] == "ok"


def test_security_status(client):
    r = client.get("/v1/security/status")
    assert r.status_code == 200
    status = r.json()
    assert status["status"] == "operational"
    assert status["default_policy"] == "deny"
    assert "epoch" in status["layers"]["6_data"]
    assert status["layers"]["5_ai"] == "active"
    assert status["layers"]["7_execution"] == "sandbox policy active"


def test_metrics_endpoint(client):
    r = client.get("/metrics")
    assert r.status_code == 200
    assert "sentinel_crypto_epochs_total" in r.text
    assert "sentinel_crypto_epoch_active" in r.text
    assert "sentinel_authorize_total" in r.text


def test_authorize_flow(client):
    # Allowed request
    r = client.post("/v1/authorize", json={
        "identity": "agent-007",
        "role": "admin",
        "method": "GET",
        "path": "/api/v1/telemetry",
        "body_size": 256,
        "zone": "user"
    })
    assert r.status_code == 200
    assert r.json()["allow"] is True
    assert r.json()["action"] == "ALLOW"

    # Blocked due to missing identity
    r_bad = client.post("/v1/authorize", json={
        "identity": "",
        "role": "admin",
        "method": "GET",
        "path": "/api/v1/telemetry",
        "body_size": 256,
        "zone": "user"
    })
    # FastAPI validation will catch min_length=1
    assert r_bad.status_code == 422


def test_ai_tool_authorization(client):
    # Safe tool
    r = client.post("/v1/ai/tool/authorize", json={
        "identity": "brahma",
        "role": "user",
        "tool": "read_file",
        "approved": False
    })
    assert r.status_code == 200
    assert r.json()["allow"] is True

    # High risk tool without approval
    r_risky = client.post("/v1/ai/tool/authorize", json={
        "identity": "brahma",
        "role": "developer",
        "tool": "shell",
        "approved": False
    })
    assert r_risky.status_code == 200
    assert r_risky.json()["allow"] is False
    assert r_risky.json()["action"] == "REQUIRE_APPROVAL"


def test_execution_sandbox_authorization(client):
    # Sandboxed allowed command
    r = client.post("/v1/execute/authorize", json={
        "identity": "brahma",
        "role": "developer",
        "command": "python -m pytest tests/",
        "sandbox": True
    })
    assert r.status_code == 200
    assert r.json()["allow"] is True

    # Unsandboxed execution strictly denied
    r_unsandboxed = client.post("/v1/execute/authorize", json={
        "identity": "brahma",
        "role": "admin",
        "command": "python -m pytest tests/",
        "sandbox": False
    })
    assert r_unsandboxed.status_code == 200
    assert r_unsandboxed.json()["allow"] is False
    assert r_unsandboxed.json()["reason"] == "execution_requires_sandbox"


def test_identity_authorization_and_revocation(client):
    # Authorize identity
    r = client.post("/v1/identity/authorize", json={
        "subject": "usr-1234",
        "roles": ["developer"],
        "scopes": ["read", "write"],
        "required_scope": "read",
        "resource": "project:sec",
        "zone": "user"
    })
    assert r.status_code == 200
    assert r.json()["allow"] is True

    # Revoke subject
    r_rev = client.post("/v1/identity/revoke", json={"subject": "usr-1234"})
    assert r_rev.status_code == 200
    assert r_rev.json()["revoked"] is True

    # Re-check authorization should be blocked now
    r_after = client.post("/v1/identity/authorize", json={
        "subject": "usr-1234",
        "roles": ["developer"],
        "scopes": ["read", "write"],
        "required_scope": "read",
        "resource": "project:sec",
        "zone": "user"
    })
    assert r_after.status_code == 200
    assert r_after.json()["allow"] is False
    assert r_after.json()["reason"] == "identity_revoked"


def test_adaptive_crypto_vault_lifecycle(client):
    # Check initial status
    r_status = client.get("/v1/crypto/status")
    assert r_status.status_code == 200
    status_data = r_status.json()
    assert status_data["scheme"] == "SENTINEL-2X-AES256-GCM-ADAPTIVE"
    initial_epoch = status_data["active_epoch"]["epoch_id"]

    # Seal plaintext
    r_seal = client.post("/v1/crypto/seal", json={
        "plaintext": "Classified Sentinel Mission Data",
        "aad": "mission-42"
    })
    assert r_seal.status_code == 200
    envelope = r_seal.json()["envelope"]
    assert envelope["crypto_epoch"] == initial_epoch

    # Decrypt plaintext
    r_open = client.post("/v1/crypto/open", json={
        "envelope": envelope,
        "aad": "mission-42"
    })
    assert r_open.status_code == 200
    assert r_open.json()["plaintext"] == "Classified Sentinel Mission Data"

    # Rotate administratively
    r_rot = client.post("/v1/crypto/rotate", json={"reason": "administrative"})
    assert r_rot.status_code == 200
    new_epoch = r_rot.json()["new_epoch_id"]
    assert new_epoch != initial_epoch

    # Old envelope is still decryptable within grace period
    r_open_old = client.post("/v1/crypto/open", json={
        "envelope": envelope,
        "aad": "mission-42"
    })
    assert r_open_old.status_code == 200
    assert r_open_old.json()["plaintext"] == "Classified Sentinel Mission Data"

    # Emergency rotation revokes the previous epoch
    r_emerg = client.post("/v1/crypto/rotate", json={"reason": "emergency"})
    assert r_emerg.status_code == 200
    emerg_epoch = r_emerg.json()["new_epoch_id"]
    assert emerg_epoch != new_epoch

    # Now sealing under the emergency epoch works
    r_seal_new = client.post("/v1/crypto/seal", json={
        "plaintext": "Post-emergency secure data",
        "aad": "mission-43"
    })
    assert r_seal_new.status_code == 200
    assert r_seal_new.json()["envelope"]["crypto_epoch"] == emerg_epoch


def test_crypto_tamper_rejection(client):
    r_seal = client.post("/v1/crypto/seal", json={"plaintext": "confidential"})
    assert r_seal.status_code == 200
    env = r_seal.json()["envelope"]

    # Tamper with outer ciphertext
    env["outer_ct"] = env["outer_ct"][:-2] + "xx"
    r_bad = client.post("/v1/crypto/open", json={"envelope": env})
    assert r_bad.status_code == 400


def test_event_logging(client):
    r = client.post("/v1/events", json={
        "source": "suricata-forwarder",
        "event_type": "port_scan_detected",
        "severity": "WARNING",
        "metadata": {"src_ip": "10.10.40.105", "dest_port": 22}
    })
    assert r.status_code == 200
    assert r.json()["accepted"] is True
    assert "event_id" in r.json()
