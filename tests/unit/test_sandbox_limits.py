import os
import sys

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


@pytest.mark.skipif(os.name != "nt", reason="Windows Job Object integration")
def test_windows_job_backend_launches_suspended_process_after_binding(tmp_path) -> None:
    backend = WindowsJobObjectBackend()

    process, binding = backend.launch(
        (sys.executable, "-c", "print('isolated-ok')"),
        working_directory=str(tmp_path),
        environment={"SYSTEMROOT": os.environ["SYSTEMROOT"]},
        limits=IsolationLimits(cpu_time_seconds=2, memory_bytes=32 * 1024 * 1024),
    )
    try:
        stdout, stderr = process.communicate(timeout=5)
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=5)
        binding.close()

    assert process.returncode == 0
    assert stdout.decode().strip() == "isolated-ok"
    assert stderr == b""


@pytest.mark.skipif(os.name != "nt", reason="Windows Job Object integration")
@pytest.mark.parametrize(
    ("code", "limits"),
    (
            ("while True: pass", IsolationLimits(cpu_time_seconds=0.5)),
        (
            "bytearray(256 * 1024 * 1024)",
            IsolationLimits(cpu_time_seconds=2, memory_bytes=32 * 1024 * 1024),
        ),
    ),
)
def test_windows_job_backend_enforces_resource_ceiling(tmp_path, code, limits) -> None:
    process, binding = WindowsJobObjectBackend().launch(
        (sys.executable, "-c", code),
        working_directory=str(tmp_path),
        environment={"SYSTEMROOT": os.environ["SYSTEMROOT"]},
        limits=limits,
    )
    try:
        process.wait(timeout=5)
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=5)
        binding.close()

    assert process.returncode != 0
