"""Deterministic startup gate for production-grade process isolation."""

from __future__ import annotations

from core.decisions.actions import DecisionAction
from core.decisions.models import SecurityDecision
from core.decisions.reasons import ReasonCode
from execution.sandbox.capabilities import HostIsolationCapabilities, probe_host_isolation_capabilities


def evaluate_hardened_readiness(
    capabilities: HostIsolationCapabilities | None = None,
) -> SecurityDecision:
    """Allow startup only when every required host control is present."""

    observed = capabilities or probe_host_isolation_capabilities()
    if not observed.hardened_ready:
        return SecurityDecision(
            decision=DecisionAction.DENY,
            risk_score=100,
            reason_codes=(ReasonCode.PROCESS_HARDENING_UNAVAILABLE,),
            metadata={
                "cpu_memory_limits": observed.cpu_memory_limits,
                "network_isolation": observed.network_isolation,
                "restricted_token": observed.restricted_token,
            },
        )
    return SecurityDecision(
        decision=DecisionAction.ALLOW,
        risk_score=0,
        reason_codes=(ReasonCode.PROCESS_HARDENING_READY,),
    )

