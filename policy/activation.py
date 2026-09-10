from __future__ import annotations

from hashlib import sha256

from core.decisions.actions import DecisionAction
from core.decisions.models import SecurityDecision
from core.decisions.reasons import ReasonCode
from core.events.factory import SecurityEventFactory
from core.events.types import TrustLevel
from policy.lifecycle import PolicyBundle, PolicyBundleRegistry
from policy.signing import PolicySignatureVerifier
from policy.storage import (
    DurablePolicyBundleStore,
    PolicyApproval,
    PolicyApprovalVerifier,
    PolicyVersionRollbackError,
    approval_matches_bundle,
)
from telemetry.audit import StructuredAuditLogger


class PolicyActivationService:
    def __init__(
        self,
        registry: PolicyBundleRegistry,
        store: DurablePolicyBundleStore,
        *,
        audit_logger: StructuredAuditLogger | None = None,
        event_factory: SecurityEventFactory | None = None,
    ) -> None:
        self._registry = registry
        self._store = store
        self._audit_logger = audit_logger or StructuredAuditLogger()
        self._event_factory = event_factory or SecurityEventFactory()
        self._registry.require_verified_publication()

    @property
    def registry(self) -> PolicyBundleRegistry:
        return self._registry

    def activate_verified(
        self,
        verifier: PolicySignatureVerifier,
        approval_verifier: PolicyApprovalVerifier,
    ) -> tuple[SecurityDecision, PolicyBundle | None]:
        try:
            loaded = self._store.load_latest()
        except PolicyVersionRollbackError:
            return self._record(_deny(ReasonCode.POLICY_VERSION_ROLLBACK), None, None, None)
        except Exception:
            return self._record(_deny(ReasonCode.POLICY_STORE_INVALID), None, None, None)

        if loaded is None:
            return self._record(_deny(ReasonCode.POLICY_APPROVAL_REQUIRED), None, None, None)
        signed, approval = loaded
        if not approval_matches_bundle(approval, signed) or not approval_verifier.verify(approval):
            return self._record(_deny(ReasonCode.POLICY_APPROVAL_INVALID), None, signed, approval)
        if not verifier.verify(signed):
            return self._record(_deny(ReasonCode.POLICY_SIGNATURE_INVALID), None, signed, approval)

        result = self._registry.publish_approved(
            signed,
            verifier,
            approval,
            approval_verifier,
        )
        decision = result.decision
        if result.bundle is not None and decision.decision is DecisionAction.ALLOW:
            decision = decision.model_copy(update={
                "reason_codes": tuple(dict.fromkeys((
                    *decision.reason_codes,
                    ReasonCode.POLICY_BUNDLE_ACTIVATED,
                ))),
            })
        return self._record(decision, result.bundle, signed, approval)

    def _record(
        self,
        decision: SecurityDecision,
        bundle: PolicyBundle | None,
        signed,
        approval: PolicyApproval | None,
    ) -> tuple[SecurityDecision, PolicyBundle | None]:
        data: dict[str, str | int] = {"activation_state": "accepted" if bundle else "denied"}
        if signed is not None:
            data.update({
                "policy_id_fingerprint": _fingerprint(signed.bundle.policy_id),
                "version": signed.bundle.version,
                "content_fingerprint": signed.bundle.content_fingerprint,
                "signer_id_fingerprint": _fingerprint(signed.signer_id),
            })
        if approval is not None:
            data.update({
                "approval_id_fingerprint": _fingerprint(approval.approval_id),
                "approver_id_fingerprint": _fingerprint(approval.approver_id),
            })
        event = self._event_factory.create(
            event_type="policy.bundle.activate",
            source="policy_activation",
            action="activate",
            target="policy_bundle",
            resource_type="policy_bundle",
            trust_level=TrustLevel.TRUSTED if bundle else TrustLevel.UNTRUSTED,
            data=data,
        )
        self._audit_logger.record(event, decision)
        return decision, bundle


def _deny(reason: ReasonCode) -> SecurityDecision:
    return SecurityDecision(decision=DecisionAction.DENY, risk_score=100, reason_codes=(reason,))


def _fingerprint(value: str) -> str:
    return sha256(value.encode("utf-8")).hexdigest()[:16]
