from __future__ import annotations

from hashlib import sha256
import json
import threading

from pydantic import BaseModel, ConfigDict, Field

from core.decisions.actions import DecisionAction
from core.decisions.models import SecurityDecision
from core.decisions.reasons import ReasonCode
from core.events.factory import SecurityEventFactory
from core.events.types import TrustLevel
from detection.models import AISecRule
from detection.parser import AISecRuleParser
from telemetry.audit import StructuredAuditLogger


class PolicyBundle(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    policy_id: str = Field(min_length=3, max_length=128, pattern=r"^[a-z0-9]+(?:[._-][a-z0-9]+)*$")
    version: int = Field(ge=1)
    content_fingerprint: str = Field(pattern=r"^[a-f0-9]{64}$")
    rules: tuple[AISecRule, ...] = Field(min_length=1, max_length=1_000)


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
        self._lock = threading.RLock()

    def publish(self, bundle: PolicyBundle) -> PolicyPublicationResult:
        with self._lock:
            event = self._event_factory.create(
                event_type="policy.bundle.publish",
                source="policy_registry",
                action="publish",
                target="policy_bundle",
                resource_type="policy_bundle",
                trust_level=TrustLevel.LIMITED,
                data={
                    "policy_id_fingerprint": _fingerprint(bundle.policy_id),
                    "version": bundle.version,
                    "content_fingerprint": bundle.content_fingerprint,
                },
            )
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

    def publish_signed(
        self,
        signed: SignedPolicyBundle,
        verifier: PolicySignatureVerifier,
    ) -> PolicyPublicationResult:
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
        return self.publish(signed.bundle)

    def current(self) -> PolicyBundle | None:
        with self._lock:
            return self._current


def parse_policy_bundle(policy_id: str, version: int, source: str) -> PolicyBundle:
    if not isinstance(source, str) or not source.strip():
        raise ValueError("policy source must be non-empty text")
    rule = AISecRuleParser().parse(source)
    canonical = json.dumps(rule.model_dump(mode="json"), sort_keys=True, separators=(",", ":"))
    return PolicyBundle(
        policy_id=policy_id,
        version=version,
        content_fingerprint=sha256(canonical.encode("utf-8")).hexdigest(),
        rules=(rule,),
    )


def _fingerprint(value: str) -> str:
    return sha256(value.encode("utf-8")).hexdigest()[:16]


def _deny(reason: ReasonCode) -> SecurityDecision:
    return SecurityDecision(decision=DecisionAction.DENY, risk_score=100, reason_codes=(reason,))
