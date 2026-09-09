from __future__ import annotations

from core.decisions.actions import DecisionAction
from core.decisions.models import SecurityDecision
from core.decisions.reasons import ReasonCode
from policy.lifecycle import PolicyBundle, PolicyBundleRegistry
from policy.signing import PolicySignatureVerifier
from policy.storage import DurablePolicyBundleStore


class PolicyActivationService:
    def __init__(self, registry: PolicyBundleRegistry, store: DurablePolicyBundleStore) -> None:
        self._registry = registry
        self._store = store

    def activate_verified(self, verifier: PolicySignatureVerifier) -> tuple[SecurityDecision, PolicyBundle | None]:
        try:
            loaded = self._store.load_latest()
            if loaded is None:
                return _deny(ReasonCode.POLICY_APPROVAL_REQUIRED), None
            signed, approval = loaded
            if approval.bundle_fingerprint != signed.bundle.content_fingerprint:
                return _deny(ReasonCode.POLICY_APPROVAL_REQUIRED), None
            if not verifier.verify(signed):
                return _deny(ReasonCode.POLICY_SIGNATURE_INVALID), None
            result = self._registry.publish(signed.bundle)
            return result.decision, result.bundle
        except Exception:
            return _deny(ReasonCode.POLICY_STORE_INVALID), None


def _deny(reason: ReasonCode) -> SecurityDecision:
    return SecurityDecision(decision=DecisionAction.DENY, risk_score=100, reason_codes=(reason,))

