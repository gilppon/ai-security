from __future__ import annotations

from hashlib import sha256
import hmac
import json
import threading
from typing import TYPE_CHECKING

from pydantic import BaseModel, ConfigDict, Field, model_validator

from core.decisions.actions import DecisionAction
from core.decisions.models import SecurityDecision
from core.decisions.reasons import ReasonCode
from core.events.factory import SecurityEventFactory
from core.events.types import TrustLevel
from detection.models import AISecRule
from detection.parser import AISecRuleParser
from telemetry.audit import StructuredAuditLogger

if TYPE_CHECKING:
    from policy.signing import PolicySignatureVerifier, SignedPolicyBundle
    from policy.storage import PolicyApproval, PolicyApprovalVerifier


class PolicyBundle(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    policy_id: str = Field(min_length=3, max_length=128, pattern=r"^[a-z0-9]+(?:[._-][a-z0-9]+)*$")
    version: int = Field(ge=1)
    content_fingerprint: str = Field(pattern=r"^[a-f0-9]{64}$")
    rules: tuple[AISecRule, ...] = Field(min_length=1, max_length=1_000)

    @model_validator(mode="after")
    def validate_content_fingerprint(self) -> "PolicyBundle":
        if not self.has_valid_fingerprint():
            raise ValueError("policy content fingerprint mismatch")
        return self

    def has_valid_fingerprint(self) -> bool:
        expected = policy_content_fingerprint(self.policy_id, self.version, self.rules)
        return hmac.compare_digest(expected, self.content_fingerprint)


class PolicyPublicationResult(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    decision: SecurityDecision
    bundle: PolicyBundle | None = None


class PolicyBundleRegistry:
    def __init__(
        self,
        *,
        audit_logger: StructuredAuditLogger | None = None,
        event_factory: SecurityEventFactory | None = None,
    ) -> None:
        self._audit_logger = audit_logger or StructuredAuditLogger()
        self._event_factory = event_factory or SecurityEventFactory()
        self._current: PolicyBundle | None = None
        self._verified_only = False
        self._lock = threading.RLock()

    def require_verified_publication(self) -> None:
        """Permanently seal this registry against unsigned publication."""
        with self._lock:
            self._verified_only = True

    def publish(self, bundle: PolicyBundle) -> PolicyPublicationResult:
        with self._lock:
            if self._verified_only:
                event = self._publication_event(bundle, trust_level=TrustLevel.UNTRUSTED)
                decision = _deny(ReasonCode.POLICY_SIGNATURE_REQUIRED)
                self._audit_logger.record(event, decision)
                return PolicyPublicationResult(decision=decision)
            return self._publish(bundle)

    def publish_signed(
        self,
        signed: SignedPolicyBundle,
        verifier: PolicySignatureVerifier,
    ) -> PolicyPublicationResult:
        with self._lock:
            if self._verified_only:
                event = self._publication_event(
                    signed.bundle,
                    trust_level=TrustLevel.UNTRUSTED,
                    signer_id=signed.signer_id,
                )
                decision = _deny(ReasonCode.POLICY_APPROVAL_REQUIRED)
                self._audit_logger.record(event, decision)
                return PolicyPublicationResult(decision=decision)
        if not verifier.verify(signed):
            event = self._event_factory.create(
                event_type="policy.bundle.verify",
                source="policy_registry",
                action="verify",
                target="policy_bundle",
                resource_type="policy_bundle",
                trust_level=TrustLevel.UNTRUSTED,
                data={
                    "signer_id_fingerprint": _fingerprint(signed.signer_id),
                    "signature_fingerprint": _fingerprint(signed.signature),
                },
            )
            decision = _deny(ReasonCode.POLICY_SIGNATURE_INVALID)
            self._audit_logger.record(event, decision)
            return PolicyPublicationResult(decision=decision)
        with self._lock:
            return self._publish(signed.bundle, signer_id=signed.signer_id)

    def publish_approved(
        self,
        signed: SignedPolicyBundle,
        verifier: PolicySignatureVerifier,
        approval: PolicyApproval,
        approval_verifier: PolicyApprovalVerifier,
    ) -> PolicyPublicationResult:
        from policy.storage import approval_matches_bundle

        if not approval_matches_bundle(approval, signed) or not approval_verifier.verify(approval):
            event = self._publication_event(
                signed.bundle,
                trust_level=TrustLevel.UNTRUSTED,
                signer_id=signed.signer_id,
            )
            decision = _deny(ReasonCode.POLICY_APPROVAL_INVALID)
            self._audit_logger.record(event, decision)
            return PolicyPublicationResult(decision=decision)
        if not verifier.verify(signed):
            event = self._publication_event(
                signed.bundle,
                trust_level=TrustLevel.UNTRUSTED,
                signer_id=signed.signer_id,
            )
            decision = _deny(ReasonCode.POLICY_SIGNATURE_INVALID)
            self._audit_logger.record(event, decision)
            return PolicyPublicationResult(decision=decision)
        with self._lock:
            return self._publish(signed.bundle, signer_id=signed.signer_id)

    def current(self) -> PolicyBundle | None:
        with self._lock:
            return self._current

    def _publish(
        self,
        bundle: PolicyBundle,
        *,
        signer_id: str | None = None,
    ) -> PolicyPublicationResult:
        event = self._publication_event(
            bundle,
            trust_level=TrustLevel.TRUSTED if signer_id else TrustLevel.LIMITED,
            signer_id=signer_id,
        )
        if not bundle.has_valid_fingerprint():
            decision = _deny(ReasonCode.POLICY_BUNDLE_INVALID)
            self._audit_logger.record(event, decision)
            return PolicyPublicationResult(decision=decision)
        if self._current is not None:
            if bundle.policy_id != self._current.policy_id:
                decision = _deny(ReasonCode.POLICY_BUNDLE_INVALID)
                self._audit_logger.record(event, decision)
                return PolicyPublicationResult(decision=decision)
            if bundle.version <= self._current.version:
                decision = _deny(ReasonCode.POLICY_VERSION_ROLLBACK)
                self._audit_logger.record(event, decision)
                return PolicyPublicationResult(decision=decision)
        decision = SecurityDecision(
            decision=DecisionAction.ALLOW,
            risk_score=0,
            reason_codes=(ReasonCode.POLICY_BUNDLE_PUBLISHED,),
        )
        self._current = bundle
        self._audit_logger.record(event, decision)
        return PolicyPublicationResult(decision=decision, bundle=bundle)

    def _publication_event(
        self,
        bundle: PolicyBundle,
        *,
        trust_level: TrustLevel,
        signer_id: str | None = None,
    ):
        data: dict[str, str | int] = {
            "policy_id_fingerprint": _fingerprint(bundle.policy_id),
            "version": bundle.version,
            "content_fingerprint": bundle.content_fingerprint,
        }
        if signer_id is not None:
            data["signer_id_fingerprint"] = _fingerprint(signer_id)
        return self._event_factory.create(
            event_type="policy.bundle.publish",
            source="policy_registry",
            action="publish",
            target="policy_bundle",
            resource_type="policy_bundle",
            trust_level=trust_level,
            data=data,
        )


def parse_policy_bundle(policy_id: str, version: int, source: str) -> PolicyBundle:
    if not isinstance(source, str) or not source.strip():
        raise ValueError("policy source must be non-empty text")
    rule = AISecRuleParser().parse(source)
    return PolicyBundle(
        policy_id=policy_id,
        version=version,
        content_fingerprint=policy_content_fingerprint(policy_id, version, (rule,)),
        rules=(rule,),
    )


def policy_content_fingerprint(
    policy_id: str,
    version: int,
    rules: tuple[AISecRule, ...],
) -> str:
    payload = {
        "policy_id": policy_id,
        "version": version,
        "rules": [rule.model_dump(mode="json") for rule in rules],
    }
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return sha256(canonical.encode("utf-8")).hexdigest()


def canonical_policy_bundle_bytes(bundle: PolicyBundle) -> bytes:
    return json.dumps(
        bundle.model_dump(mode="json"),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def _fingerprint(value: str) -> str:
    return sha256(value.encode("utf-8")).hexdigest()[:16]


def _deny(reason: ReasonCode) -> SecurityDecision:
    return SecurityDecision(decision=DecisionAction.DENY, risk_score=100, reason_codes=(reason,))
