from pathlib import Path
import os
import socket
import sys

import pytest

from core.decisions.actions import DecisionAction
from core.decisions.reasons import ReasonCode
from execution.sandbox.executor import SafeExecutor
from execution.sandbox.limits import IsolationError, IsolationLimits, ProcessIsolationBackend
from resource_security.filesystem.firewall import FilesystemFirewall
from resource_security.filesystem.models import FilesystemGrant, FilesystemOperation
from resource_security.process.firewall import ProcessFirewall
from resource_security.process.models import ProcessAuthorizationRequest, ProcessGrant
from telemetry.audit import InMemoryAuditSink, StructuredAuditLogger


def build_firewall(tmp_path: Path, *, clock=lambda: 1.0, output_limit: int = 4096) -> ProcessFirewall:
    filesystem = FilesystemFirewall((FilesystemGrant(
        root=tmp_path,
        operations=frozenset({FilesystemOperation.LIST, FilesystemOperation.READ}),
    ),))
    return ProcessFirewall((ProcessGrant(
        executable=Path(sys.executable),
        argument_prefix=(),
        working_roots=(tmp_path,),
        path_argument_indices=(1,),
        max_timeout_seconds=2,
        max_output_bytes=output_limit,
    ),), filesystem_firewall=filesystem, clock=clock, capability_ttl_seconds=1)


def authorize_script(firewall: ProcessFirewall, tmp_path: Path, script: Path):
    return firewall.authorize(ProcessAuthorizationRequest(
        argv=(sys.executable, str(script)),
        working_directory=str(tmp_path),
        timeout_seconds=1,
    ))


def test_process_authorization_mints_one_time_capability(tmp_path: Path) -> None:
    script = tmp_path / "safe.py"
    script.write_text("print('ok')", encoding="utf-8")
    firewall = build_firewall(tmp_path)

    result = authorize_script(firewall, tmp_path, script)
    spec, reason = firewall.consume(result.capability or "")
    replay, replay_reason = firewall.consume(result.capability or "")

    assert result.decision.decision is DecisionAction.ALLOW
    assert ReasonCode.PROCESS_AUTHORIZED in result.decision.reason_codes
    assert spec is not None and reason is None
    assert spec.argv[1] == str(script.resolve())
    assert replay is None and replay_reason is ReasonCode.PROCESS_CAPABILITY_REPLAYED


def test_expired_and_unknown_capabilities_are_denied(tmp_path: Path) -> None:
    now = [1.0]
    script = tmp_path / "safe.py"
    script.write_text("pass", encoding="utf-8")
    firewall = build_firewall(tmp_path, clock=lambda: now[0])
    result = authorize_script(firewall, tmp_path, script)
    now[0] = 3.0

    expired, expired_reason = firewall.consume(result.capability or "")
    unknown, unknown_reason = firewall.consume("not-a-capability")

    assert expired is None and expired_reason is ReasonCode.PROCESS_CAPABILITY_EXPIRED
    assert unknown is None and unknown_reason is ReasonCode.PROCESS_CAPABILITY_INVALID


def test_shell_flags_and_ungranted_working_directory_are_denied(tmp_path: Path) -> None:
    firewall = build_firewall(tmp_path)
    shell_flag = firewall.authorize(ProcessAuthorizationRequest(
        argv=(sys.executable, "-c", "print('unsafe')"),
        working_directory=str(tmp_path),
    ))
    outside = firewall.authorize(ProcessAuthorizationRequest(
        argv=(sys.executable, str(tmp_path / "safe.py")),
        working_directory=str(tmp_path.parent),
        timeout_seconds=1,
    ))

    assert ReasonCode.PROCESS_ARGUMENT_DENIED in shell_flag.decision.reason_codes
    assert ReasonCode.PROCESS_WORKING_DIRECTORY_DENIED in outside.decision.reason_codes


def test_safe_executor_returns_only_output_metadata_and_blocks_replay(tmp_path: Path) -> None:
    secret_output = "executor-private-output"
    script = tmp_path / "safe.py"
    script.write_text(f"print({secret_output!r})", encoding="utf-8")
    firewall = build_firewall(tmp_path)
    result = authorize_script(firewall, tmp_path, script)
    sink = InMemoryAuditSink()
    executor = SafeExecutor(firewall, audit_logger=StructuredAuditLogger(sink))

    executed = executor.execute(result.capability or "")
    replay = executor.execute(result.capability or "")

    assert executed.decision.decision is DecisionAction.ALLOW
    assert executed.stdout_bytes > 0 and executed.stdout_fingerprint is not None
    assert secret_output not in executed.model_dump_json()
    assert secret_output not in "".join(sink.records)
    assert ReasonCode.PROCESS_CAPABILITY_REPLAYED in replay.decision.reason_codes


@pytest.mark.skipif(os.name != "nt", reason="Windows Job Object integration")
def test_safe_executor_runs_with_required_windows_os_isolation(tmp_path: Path) -> None:
    script = tmp_path / "isolated.py"
    script.write_text("print('isolated')", encoding="utf-8")
    firewall = build_firewall(tmp_path)
    authorization = authorize_script(firewall, tmp_path, script)

    result = SafeExecutor(firewall, require_os_isolation=True).execute(
        authorization.capability or ""
    )

    assert result.decision.decision is DecisionAction.ALLOW
    assert ReasonCode.PROCESS_EXECUTED in result.decision.reason_codes
    assert result.stdout_bytes > 0


def test_safe_executor_terminates_output_overflow(tmp_path: Path) -> None:
    script = tmp_path / "loud.py"
    script.write_text("print('x' * 20000)", encoding="utf-8")
    firewall = build_firewall(tmp_path, output_limit=1024)
    result = authorize_script(firewall, tmp_path, script)

    executed = SafeExecutor(firewall).execute(result.capability or "")

    assert executed.decision.decision is DecisionAction.TERMINATE
    assert ReasonCode.PROCESS_OUTPUT_LIMIT in executed.decision.reason_codes


def test_safe_executor_terminates_timeout(tmp_path: Path) -> None:
    script = tmp_path / "slow.py"
    script.write_text("import time\ntime.sleep(2)", encoding="utf-8")
    firewall = build_firewall(tmp_path)
    result = firewall.authorize(ProcessAuthorizationRequest(
        argv=(sys.executable, str(script)),
        working_directory=str(tmp_path),
        timeout_seconds=0.1,
    ))

    executed = SafeExecutor(firewall).execute(result.capability or "")

    assert executed.decision.decision is DecisionAction.TERMINATE
    assert ReasonCode.PROCESS_TIMEOUT in executed.decision.reason_codes


def test_required_os_isolation_fails_before_child_creation(monkeypatch) -> None:
    created = False

    def fail_if_spawned(*args, **kwargs):
        nonlocal created
        created = True
        raise AssertionError("child process must not be created")

    class Backend(ProcessIsolationBackend):
        def launch(self, argv, *, working_directory, environment, limits):
            raise IsolationError("required OS isolation must be established before process creation")

        def apply(self, process: object, limits: IsolationLimits):
            raise AssertionError("backend must not be called after spawn")

    monkeypatch.setattr("execution.sandbox.executor.subprocess.Popen", fail_if_spawned)

    try:
        SafeExecutor._run_bounded(
            ("python", "-c", "print('unsafe')"),
            ".",
            1.0,
            1024,
            isolation_backend=Backend(),
            isolation_limits=IsolationLimits(require_os_enforcement=True),
        )
    except IsolationError as exc:
        assert "before process creation" in str(exc)
    else:
        raise AssertionError("required isolation must fail closed")
    assert created is False


def test_required_network_isolation_fails_before_child_creation(tmp_path: Path) -> None:
    marker = tmp_path / "network-bypass.txt"
    script = tmp_path / "network.py"
    script.write_text(
        f"from pathlib import Path\nPath({str(marker)!r}).write_text('ran')",
        encoding="utf-8",
    )
    firewall = build_firewall(tmp_path)
    authorization = authorize_script(firewall, tmp_path, script)

    class Backend(ProcessIsolationBackend):
        def launch(self, argv, *, working_directory, environment, limits):
            assert limits.network_mode == "deny"
            raise IsolationError(
                "network isolation unavailable", stage="NETWORK_BOUNDARY"
            )

        def apply(self, process: object, limits: IsolationLimits):
            raise AssertionError("network isolation must be established before spawn")

    result = SafeExecutor(
        firewall,
        isolation_backend=Backend(),
        require_network_isolation=True,
    ).execute(authorization.capability or "")

    assert result.decision.decision is DecisionAction.DENY
    assert ReasonCode.PROCESS_NETWORK_ISOLATION_UNAVAILABLE in result.decision.reason_codes
    assert result.decision.metadata == {
        "isolation_failure_stage": "NETWORK_BOUNDARY"
    }
    assert marker.exists() is False


@pytest.mark.skipif(os.name != "nt", reason="Windows AppContainer integration")
@pytest.mark.native_isolation
def test_appcontainer_enforces_token_network_and_read_only_workspace(
    tmp_path: Path, monkeypatch
) -> None:
    marker = tmp_path / "write-bypass.txt"
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]
    monkeypatch.setenv("AI_SECURITY_TEST_SECRET", "must-not-cross-boundary")
    script = tmp_path / "appcontainer_probe.py"
    script.write_text(
        """import ctypes
import socket
import subprocess
import sys
from ctypes import wintypes
from pathlib import Path

advapi = ctypes.WinDLL('advapi32', use_last_error=True)
kernel = ctypes.WinDLL('kernel32', use_last_error=True)
kernel.GetCurrentProcess.restype = wintypes.HANDLE
advapi.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
advapi.GetTokenInformation.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
token = wintypes.HANDLE()
if not advapi.OpenProcessToken(kernel.GetCurrentProcess(), 8, ctypes.byref(token)):
    raise SystemExit(10)
is_appcontainer = wintypes.DWORD()
size = wintypes.DWORD()
if not advapi.GetTokenInformation(token, 29, ctypes.byref(is_appcontainer), 4, ctypes.byref(size)):
    raise SystemExit(11)
if not is_appcontainer.value:
    raise SystemExit(12)
if __import__('os').environ.get('AI_SECURITY_TEST_SECRET'):
    raise SystemExit(17)
descendant_probe = '''import ctypes
from ctypes import wintypes
a=ctypes.WinDLL('advapi32',use_last_error=True)
k=ctypes.WinDLL('kernel32',use_last_error=True)
k.GetCurrentProcess.restype=wintypes.HANDLE
a.OpenProcessToken.argtypes=[wintypes.HANDLE,wintypes.DWORD,ctypes.POINTER(wintypes.HANDLE)]
h=wintypes.HANDLE(); v=wintypes.DWORD(); n=wintypes.DWORD()
ok=a.OpenProcessToken(k.GetCurrentProcess(),8,ctypes.byref(h))
ok=ok and a.GetTokenInformation(h,29,ctypes.byref(v),4,ctypes.byref(n))
raise SystemExit(0 if ok and v.value else 18)
'''
if subprocess.run([sys.executable, '-c', descendant_probe], shell=False).returncode:
    raise SystemExit(18)
try:
    Path(r'__MARKER__').write_text('sandbox escaped', encoding='utf-8')
except OSError:
    pass
else:
    raise SystemExit(13)
try:
    socket.create_connection(('127.0.0.1', __PORT__), timeout=0.25)
except OSError:
    pass
else:
    raise SystemExit(14)
""".replace("__MARKER__", str(marker)).replace("__PORT__", str(port)),
        encoding="utf-8",
    )
    firewall = build_firewall(tmp_path)
    authorization = authorize_script(firewall, tmp_path, script)

    try:
        result = SafeExecutor(
            firewall,
            require_os_isolation=True,
            require_network_isolation=True,
        ).execute(authorization.capability or "")
    finally:
        listener.close()

    diagnostic = (
        "AISCP_SAFE_DIAGNOSTIC: "
        f"decision={result.decision.decision.value};"
        "reason_codes="
        f"{','.join(code.value for code in result.decision.reason_codes)};"
        f"exit_code={result.exit_code if result.exit_code is not None else 'none'};"
        "failure_stage="
        f"{result.decision.metadata.get('isolation_failure_stage', 'none')};"
        "os_error_code="
        f"{result.decision.metadata.get('isolation_error_code', 'none')};"
        f"marker_exists={marker.exists()}"
    )
    if result.decision.decision is DecisionAction.DENY:
        assert result.decision.reason_codes[0] in {
            ReasonCode.PROCESS_ISOLATION_UNAVAILABLE,
            ReasonCode.PROCESS_ISOLATION_FAILED,
        }, diagnostic
        assert result.exit_code is None, diagnostic
        assert marker.exists() is False, diagnostic
        return

    assert result.decision.decision is DecisionAction.ALLOW, diagnostic
    assert result.exit_code == 0, diagnostic
    assert marker.exists() is False, diagnostic
