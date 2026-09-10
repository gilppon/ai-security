from fastapi.testclient import TestClient

from app.bootstrap import create_app
from app.config import Settings
from policy.lifecycle import parse_policy_bundle
from policy.signing import sign_policy_bundle
from policy.storage import DurablePolicyBundleStore, create_approval


POLICY_SOURCE = """
id: ASEC-POLICY-RUNTIME-DENY
title: Deny prompt scans
category: core
severity: critical
when:
  event_type: prompt.scan
match:
  source: user
risk:
  score: 100
actions: [deny, audit]
"""


def test_verified_policy_is_installed_into_runtime_detection(tmp_path) -> None:
    signer_key = b"s" * 32
    approver_key = b"a" * 32
    bundle = parse_policy_bundle("runtime-policy", 1, POLICY_SOURCE)
    signed = sign_policy_bundle(bundle, signer_id="release-key", key=signer_key)
    approval = create_approval(
        "approval-1",
        "security-approver",
        signed,
        key=approver_key,
    )
    store = DurablePolicyBundleStore(tmp_path / "policy.jsonl")
    store.append(signed, approval)
    app = create_app(
        Settings(
            environment="production",
            require_verified_policy=True,
            policy_signer_id="release-key",
            policy_signing_key_hex=signer_key.hex(),
            policy_approver_id="security-approver",
            policy_approval_key_hex=approver_key.hex(),
            policy_store_path=str(tmp_path / "policy.jsonl"),
        ),
    )

    with TestClient(app) as client:
        response = client.post("/v1/security/prompt/scan", json={"prompt": "Hello"})

    assert response.status_code == 200
    decision = response.json()["decision"]
    assert decision["decision"] == "DENY"
    assert "ASEC-POLICY-RUNTIME-DENY" in decision["matched_rules"]
