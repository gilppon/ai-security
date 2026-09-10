from __future__ import annotations

from dataclasses import dataclass
import json

from pydantic import SecretStr

from app.config import Settings
from core.decisions.actions import DecisionAction
from core.decisions.models import SecurityDecision
from core.decisions.reasons import ReasonCode
from core.events.factory import SecurityEventFactory
from core.events.types import TrustLevel
from policy.activation import PolicyActivationService
from policy.lifecycle import PolicyBundle
from policy.signing import PolicySignatureVerifier
from policy.storage import PolicyApprovalVerifier
from policy.storage import DurablePolicyBundleStore
from policy.lifecycle import PolicyBundleRegistry
from telemetry.audit import StructuredAuditLogger


@dataclass(frozen=True, slots=True)
class PolicyTrustVerifiers:
    signatures: PolicySignatureVerifier
    approvals: PolicyApprovalVerifier


def verifiers_from_settings(settings: Settings) -> PolicyTrustVerifiers | None:
    if settings.environment == "production" and not settings.require_verified_policy:
        raise RuntimeError("production startup requires verified policy")
    if not settings.require_verified_policy:
        return None

    signing_keys = _key_map(
        single_id=settings.policy_signer_id,
        single_key=settings.policy_signing_key_hex,
        keys_json=settings.policy_signing_keys_json,
        label="signer",
    )
    approval_keys = _key_map(
        single_id=settings.policy_approver_id,
        single_key=settings.policy_approval_key_hex,
        keys_json=settings.policy_approval_keys_json,
        label="approver",
    )
    return PolicyTrustVerifiers(
        signatures=PolicySignatureVerifier(
            signing_keys,
            revoked_signer_ids=frozenset(settings.policy_revoked_signer_ids),
        ),
        approvals=PolicyApprovalVerifier(
            approval_keys,
            revoked_approver_ids=frozenset(settings.policy_revoked_approver_ids),
        ),
    )


def verifier_from_settings(settings: Settings) -> PolicySignatureVerifier | None:
    """Backward-compatible access to the configured signature verifier."""
    verifiers = verifiers_from_settings(settings)
    return verifiers.signatures if verifiers is not None else None


def activate_policy_or_raise(
    settings: Settings,
    activation_service: PolicyActivationService | None,
) -> PolicyBundle | None:
    verifiers = verifiers_from_settings(settings)
    if verifiers is None:
        return None
    if activation_service is None:
        raise RuntimeError("verified policy startup requires activation service")
    decision, bundle = activation_service.activate_verified(
        verifiers.signatures,
        verifiers.approvals,
    )
    if bundle is None or decision.decision.value != "ALLOW":
        raise RuntimeError("verified policy activation denied")
    return bundle


def activation_service_from_settings(
    settings: Settings,
    *,
    audit_logger: StructuredAuditLogger | None = None,
) -> PolicyActivationService | None:
    if not settings.require_verified_policy or settings.policy_store_path is None:
        return None
    logger = audit_logger or StructuredAuditLogger()
    registry = PolicyBundleRegistry(audit_logger=logger)
    try:
        store = DurablePolicyBundleStore(settings.policy_store_path)
    except Exception as exc:
        event = SecurityEventFactory().create(
            event_type="policy.bundle.activate",
            source="policy_startup",
            action="activate",
            target="policy_bundle",
            resource_type="policy_bundle",
            trust_level=TrustLevel.UNTRUSTED,
            data={"activation_state": "denied", "store_state": "unavailable"},
        )
        decision = SecurityDecision(
            decision=DecisionAction.DENY,
            risk_score=100,
            reason_codes=(ReasonCode.POLICY_STORE_INVALID,),
        )
        logger.record(event, decision)
        raise RuntimeError("verified policy store unavailable") from exc
    return PolicyActivationService(registry, store, audit_logger=logger)


def _key_map(
    *,
    single_id: str | None,
    single_key: SecretStr | None,
    keys_json: SecretStr | None,
    label: str,
) -> dict[str, bytes]:
    keys: dict[str, bytes] = {}
    if (single_id is None) != (single_key is None):
        raise RuntimeError(f"verified policy startup requires matching {label} id and key")
    if single_id is not None and single_key is not None:
        keys[single_id] = _decode_key(single_key.get_secret_value(), label)
    if keys_json is not None:
        try:
            payload = json.loads(keys_json.get_secret_value())
        except json.JSONDecodeError as exc:
            raise RuntimeError(f"policy {label} key map must be valid JSON") from exc
        if not isinstance(payload, dict) or not payload:
            raise RuntimeError(f"policy {label} key map must be a non-empty object")
        for identity, encoded in payload.items():
            if not isinstance(identity, str) or not identity or not isinstance(encoded, str):
                raise RuntimeError(f"policy {label} key map contains an invalid entry")
            decoded = _decode_key(encoded, label)
            if identity in keys and keys[identity] != decoded:
                raise RuntimeError(f"policy {label} key map contains a conflicting identity")
            keys[identity] = decoded
    if not keys:
        raise RuntimeError(f"verified policy startup requires {label} identities and keys")
    return keys


def _decode_key(value: str, label: str) -> bytes:
    try:
        decoded = bytes.fromhex(value)
    except ValueError as exc:
        raise RuntimeError(f"policy {label} key must be hexadecimal") from exc
    if len(decoded) < 32:
        raise RuntimeError(f"policy {label} key must contain at least 32 bytes")
    return decoded
