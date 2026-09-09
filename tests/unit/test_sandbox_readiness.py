from execution.sandbox.capabilities import HostIsolationCapabilities
from execution.sandbox.readiness import evaluate_hardened_readiness
from core.decisions.actions import DecisionAction
from core.decisions.reasons import ReasonCode


def test_hardened_readiness_denies_missing_controls() -> None:
    decision = evaluate_hardened_readiness(
        HostIsolationCapabilities(cpu_memory_limits=True, network_isolation=False, restricted_token=False)
    )

    assert decision.decision is DecisionAction.DENY
    assert decision.reason_codes == (ReasonCode.PROCESS_HARDENING_UNAVAILABLE,)


def test_hardened_readiness_allows_complete_host() -> None:
    decision = evaluate_hardened_readiness(
        HostIsolationCapabilities(cpu_memory_limits=True, network_isolation=True, restricted_token=True)
    )

    assert decision.decision is DecisionAction.ALLOW
    assert decision.reason_codes == (ReasonCode.PROCESS_HARDENING_READY,)

