from __future__ import annotations

from collections.abc import Iterable
import threading

from core.context.models import SecurityContext
from core.contracts import DetectionEngineContract, PolicyEngineContract, RiskEngineContract
from core.decisions.models import SecurityDecision
from core.events.models import SecurityEvent
from detection.engine import DetectionEngine
from detection.models import DetectionFinding
from policy.lifecycle import PolicyBundleRegistry


class ActivePolicyDetector:
    """Expose the registry's immutable active bundle as a finding producer."""

    def __init__(self, registry: PolicyBundleRegistry) -> None:
        self._registry = registry
        self._cached_fingerprint: str | None = None
        self._engine = DetectionEngine()
        self._lock = threading.RLock()

    def detect(
        self,
        event: SecurityEvent,
        context: SecurityContext,
    ) -> tuple[DetectionFinding, ...]:
        bundle = self._registry.current()
        if bundle is None:
            return ()
        with self._lock:
            if bundle.content_fingerprint != self._cached_fingerprint:
                self._engine = DetectionEngine(bundle.rules)
                self._cached_fingerprint = bundle.content_fingerprint
            engine = self._engine
        return engine.detect(event, context)


def decide_with_active_policy(
    *,
    event: SecurityEvent,
    context: SecurityContext,
    findings: Iterable[DetectionFinding],
    risk_engine: RiskEngineContract,
    policy_engine: PolicyEngineContract,
    policy_detector: DetectionEngineContract | None,
) -> SecurityDecision:
    combined = tuple(findings)
    if policy_detector is not None:
        combined = (*combined, *policy_detector.detect(event, context))
    risk = risk_engine.score(event, context, combined)
    return policy_engine.decide(risk, combined)
