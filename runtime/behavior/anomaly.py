from datetime import timedelta

from core.decisions.reasons import ReasonCode
from detection.models import Severity
from runtime.behavior.correlation import RuntimeSequenceCorrelator
from runtime.behavior.profiles import BehaviorProfile
from runtime.models import (
    RuntimeFinding,
    RuntimeObservation,
    RuntimeOutcome,
)


class RuntimeAnomalyDetector:
    def __init__(
        self,
        correlator: RuntimeSequenceCorrelator | None = None,
    ) -> None:
        self._correlator = correlator or RuntimeSequenceCorrelator()

    def detect(
        self,
        observations: tuple[RuntimeObservation, ...],
        profile: BehaviorProfile,
    ) -> tuple[RuntimeFinding, ...]:
        if not observations:
            return ()
        current = observations[-1]
        cutoff = current.timestamp - timedelta(seconds=profile.window_seconds)
        window = tuple(item for item in observations if item.timestamp >= cutoff)
        findings: list[RuntimeFinding] = []

        if current.activity not in profile.allowed_activities:
            findings.append(_finding(
                "RUNTIME_ACTIVITY_POLICY_VIOLATION",
                ReasonCode.RUNTIME_ACTIVITY_DENIED,
                100,
                Severity.CRITICAL,
            ))
        if len(window) > profile.max_events_per_window:
            findings.append(_finding(
                "RUNTIME_EVENT_RATE_BURST",
                ReasonCode.RUNTIME_RATE_ANOMALY,
                80,
                Severity.CRITICAL,
            ))
        denied_count = sum(
            item.outcome in {RuntimeOutcome.BLOCKED, RuntimeOutcome.FAILED}
            for item in window
        )
        if denied_count > profile.max_denied_per_window:
            findings.append(_finding(
                "RUNTIME_REPEATED_DENIALS",
                ReasonCode.RUNTIME_DENIAL_BURST,
                80,
                Severity.CRITICAL,
            ))
        targets = {
            item.target_fingerprint
            for item in window
            if item.target_fingerprint is not None
        }
        if len(targets) > profile.max_distinct_targets_per_window:
            findings.append(_finding(
                "RUNTIME_TARGET_FANOUT_BURST",
                ReasonCode.RUNTIME_TARGET_FANOUT,
                70,
                Severity.HIGH,
            ))

        findings.extend(self._correlator.correlate(window))
        return tuple(sorted(findings, key=lambda item: item.code))


def _finding(
    code: str,
    reason: ReasonCode,
    risk_score: int,
    severity: Severity,
) -> RuntimeFinding:
    return RuntimeFinding(
        code=code,
        severity=severity,
        risk_score=risk_score,
        reason_code=reason.value,
    )
