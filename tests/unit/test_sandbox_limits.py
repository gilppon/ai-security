import pytest

from execution.sandbox.limits import IsolationLimits, UnavailableIsolationBackend, WindowsJobObjectBackend


def test_isolation_limits_are_bounded_and_immutable() -> None:
    limits = IsolationLimits(cpu_time_seconds=2, memory_bytes=32 * 1024 * 1024)

    assert limits.cpu_time_seconds == 2
    assert limits.network_mode == "inherit"
    with pytest.raises(ValueError):
        limits.memory_bytes = 64 * 1024 * 1024


def test_isolation_limits_reject_unbounded_values() -> None:
    with pytest.raises(ValueError):
        IsolationLimits(memory_bytes=1024)
    with pytest.raises(ValueError):
        IsolationLimits(cpu_time_seconds=301)


def test_unavailable_backend_fails_closed_when_required() -> None:
    backend = UnavailableIsolationBackend()
    with pytest.raises(RuntimeError):
        backend.apply(object(), IsolationLimits(require_os_enforcement=True))


def test_job_backend_never_claims_network_isolation() -> None:
    with pytest.raises(RuntimeError, match="network"):
        WindowsJobObjectBackend().apply(object(), IsolationLimits(network_mode="deny"))
