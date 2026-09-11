"""Create an ephemeral verified policy store for the container release smoke test."""

from __future__ import annotations

import json
import os
from pathlib import Path

from app.config import Settings
from policy.lifecycle import parse_policy_bundle
from policy.signing import sign_policy_bundle
from policy.storage import DurablePolicyBundleStore, create_approval


POLICY_SOURCE = """
id: ASEC-RELEASE-SMOKE
title: Release container smoke policy
category: core
severity: info
when:
  event_type: release.smoke
match:
  source: release_ci
risk:
  score: 0
actions: [audit]
"""


def main() -> int:
    if os.environ.get("CI", "").lower() != "true":
        raise RuntimeError("release policy fixture is restricted to CI")
    settings = Settings.from_environment()
    if settings.environment != "production" or not settings.require_verified_policy:
        raise RuntimeError("release fixture requires production verified-policy settings")
    if (
        settings.policy_signer_id is None
        or settings.policy_signing_key_hex is None
        or settings.policy_approver_id is None
        or settings.policy_approval_key_hex is None
        or settings.policy_store_path is None
    ):
        raise RuntimeError("release fixture trust inputs are incomplete")

    path = Path(settings.policy_store_path)
    if not path.is_absolute() or path.exists() or not path.parent.is_dir():
        raise RuntimeError("release fixture store must be a new absolute path")
    signer_key = _decode_key(settings.policy_signing_key_hex.get_secret_value())
    approver_key = _decode_key(settings.policy_approval_key_hex.get_secret_value())
    bundle = parse_policy_bundle("release-smoke-policy", 1, POLICY_SOURCE)
    signed = sign_policy_bundle(
        bundle,
        signer_id=settings.policy_signer_id,
        key=signer_key,
    )
    approval = create_approval(
        "release-smoke-approval",
        settings.policy_approver_id,
        signed,
        key=approver_key,
    )
    DurablePolicyBundleStore(path).append(signed, approval)
    print(json.dumps({"content_fingerprint": bundle.content_fingerprint}, sort_keys=True))
    return 0


def _decode_key(value: str) -> bytes:
    try:
        key = bytes.fromhex(value)
    except ValueError as exc:
        raise RuntimeError("release fixture key must be hexadecimal") from exc
    if len(key) < 32:
        raise RuntimeError("release fixture key must contain at least 32 bytes")
    return key


if __name__ == "__main__":
    raise SystemExit(main())
