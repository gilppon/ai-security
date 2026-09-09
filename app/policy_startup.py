from __future__ import annotations

from app.config import Settings
from policy.activation import PolicyActivationService
from policy.signing import PolicySignatureVerifier


def verifier_from_settings(settings: Settings) -> PolicySignatureVerifier | None:
    if settings.environment == "production" and not settings.require_verified_policy:
        raise RuntimeError("production startup requires verified policy")
    if not settings.require_verified_policy:
        return None
    if not settings.policy_signer_id or not settings.policy_signing_key_hex:
        raise RuntimeError("verified policy startup requires signer id and key")
    try:
        key = bytes.fromhex(settings.policy_signing_key_hex)
    except ValueError as exc:
        raise RuntimeError("policy signing key must be hexadecimal") from exc
    return PolicySignatureVerifier({settings.policy_signer_id: key})


def activate_policy_or_raise(
    settings: Settings,
    activation_service: PolicyActivationService | None,
) -> None:
    verifier = verifier_from_settings(settings)
    if verifier is None:
        return
    if activation_service is None:
        raise RuntimeError("verified policy startup requires activation service")
    decision, bundle = activation_service.activate_verified(verifier)
    if bundle is None or decision.decision.value != "ALLOW":
        raise RuntimeError("verified policy activation denied")
