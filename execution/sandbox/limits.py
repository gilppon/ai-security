"""Replaceable OS isolation backends for the safe process executor.

The policy layer remains deterministic; this module only applies already
authorized limits to a spawned process.  A backend must fail closed when a
requested control cannot be enforced by the host OS.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
import ctypes
import io
import os
import subprocess
import threading
import uuid
from typing import Literal, Protocol

from pydantic import BaseModel, ConfigDict, Field


_CREATE_SUSPENDED = 0x00000004
_CREATE_UNICODE_ENVIRONMENT = 0x00000400


class IsolationLimits(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    cpu_time_seconds: float = Field(default=30.0, ge=0.1, le=300.0)
    memory_bytes: int = Field(default=256 * 1024 * 1024, ge=16 * 1024 * 1024, le=4 * 1024**3)
    network_mode: Literal["inherit", "deny"] = "inherit"
    require_os_enforcement: bool = False


class IsolationError(RuntimeError):
    """Raised when the host cannot enforce a requested isolation control."""


class IsolationBinding(Protocol):
    def close(self) -> None: ...


class ProcessIsolationBackend(ABC):
    def launch(
        self,
        argv: tuple[str, ...],
        *,
        working_directory: str,
        environment: dict[str, str],
        limits: IsolationLimits,
    ) -> tuple[object, IsolationBinding]:
        """Launch a child only after required isolation is prepared.

        Backends that cannot establish isolation before user code runs must
        leave this default fail-closed implementation in place.
        """
        del argv, working_directory, environment, limits
        raise IsolationError("pre-launch OS isolation backend unavailable")

    @abstractmethod
    def apply(self, process: object, limits: IsolationLimits) -> IsolationBinding:
        raise NotImplementedError


@dataclass(frozen=True)
class _NoopBinding:
    def close(self) -> None:
        return None


class UnavailableIsolationBackend(ProcessIsolationBackend):
    def apply(self, process: object, limits: IsolationLimits) -> IsolationBinding:
        del process
        if limits.require_os_enforcement:
            raise IsolationError("OS process isolation backend unavailable")
        return _NoopBinding()


if os.name == "nt":
    from ctypes import wintypes
    import flatbuffers

    _DWORD = ctypes.c_uint32
    _SIZE_T = ctypes.c_size_t
    _ULARGE_INTEGER = ctypes.c_ulonglong
    _TH32CS_SNAPTHREAD = 0x00000004
    _THREAD_SUSPEND_RESUME = 0x0002
    _INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value
    _WAIT_OBJECT_0 = 0
    _WAIT_TIMEOUT = 258
    _STILL_ACTIVE = 259

    _KERNEL32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _KERNEL32.CreateJobObjectW.restype = wintypes.HANDLE
    _KERNEL32.SetInformationJobObject.argtypes = [
        wintypes.HANDLE,
        _DWORD,
        ctypes.c_void_p,
        _DWORD,
    ]
    _KERNEL32.SetInformationJobObject.restype = wintypes.BOOL
    _KERNEL32.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
    _KERNEL32.AssignProcessToJobObject.restype = wintypes.BOOL
    _KERNEL32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
    _KERNEL32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
    _KERNEL32.OpenThread.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    _KERNEL32.OpenThread.restype = wintypes.HANDLE
    _KERNEL32.ResumeThread.argtypes = [wintypes.HANDLE]
    _KERNEL32.ResumeThread.restype = wintypes.DWORD
    _KERNEL32.CloseHandle.argtypes = [wintypes.HANDLE]
    _KERNEL32.CloseHandle.restype = wintypes.BOOL
    _KERNEL32.GetExitCodeProcess.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
    _KERNEL32.GetExitCodeProcess.restype = wintypes.BOOL
    _KERNEL32.TerminateProcess.argtypes = [wintypes.HANDLE, wintypes.UINT]
    _KERNEL32.TerminateProcess.restype = wintypes.BOOL
    _KERNEL32.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    _KERNEL32.WaitForSingleObject.restype = wintypes.DWORD
    _KERNEL32.QueryInformationJobObject.argtypes = [
        wintypes.HANDLE, _DWORD, ctypes.c_void_p, _DWORD, ctypes.POINTER(_DWORD)
    ]
    _KERNEL32.QueryInformationJobObject.restype = wintypes.BOOL
    _KERNEL32.TerminateJobObject.argtypes = [wintypes.HANDLE, wintypes.UINT]
    _KERNEL32.TerminateJobObject.restype = wintypes.BOOL

    class _StartupInfo(ctypes.Structure):
        _fields_ = [
            ("cb", wintypes.DWORD), ("lpReserved", wintypes.LPWSTR),
            ("lpDesktop", wintypes.LPWSTR), ("lpTitle", wintypes.LPWSTR),
            ("dwX", wintypes.DWORD), ("dwY", wintypes.DWORD),
            ("dwXSize", wintypes.DWORD), ("dwYSize", wintypes.DWORD),
            ("dwXCountChars", wintypes.DWORD), ("dwYCountChars", wintypes.DWORD),
            ("dwFillAttribute", wintypes.DWORD), ("dwFlags", wintypes.DWORD),
            ("wShowWindow", wintypes.WORD), ("cbReserved2", wintypes.WORD),
            ("lpReserved2", ctypes.POINTER(ctypes.c_byte)),
            ("hStdInput", wintypes.HANDLE), ("hStdOutput", wintypes.HANDLE),
            ("hStdError", wintypes.HANDLE),
        ]

    class _ProcessInformation(ctypes.Structure):
        _fields_ = [
            ("hProcess", wintypes.HANDLE), ("hThread", wintypes.HANDLE),
            ("dwProcessId", wintypes.DWORD), ("dwThreadId", wintypes.DWORD),
        ]

    class _WindowsSandboxProcess:
        """Minimal Popen-compatible handle for an AppContainer child."""

        def __init__(self, process_handle: int, process_id: int, identity: str) -> None:
            self._handle = process_handle
            self.pid = process_id
            self.returncode: int | None = None
            self._identity = identity
            # The experimental API forbids inherited handles. Hardened runs
            # therefore expose no raw child output instead of weakening the
            # AppContainer boundary.
            self.stdout = io.BytesIO()
            self.stderr = io.BytesIO()

        def poll(self) -> int | None:
            code = wintypes.DWORD()
            if not _KERNEL32.GetExitCodeProcess(self._handle, ctypes.byref(code)):
                raise IsolationError("failed to query AppContainer process")
            if code.value == _STILL_ACTIVE:
                return None
            self.returncode = int(code.value)
            return self.returncode

        def wait(self, timeout: float | None = None) -> int:
            milliseconds = 0xFFFFFFFF if timeout is None else max(0, int(timeout * 1000))
            result = _KERNEL32.WaitForSingleObject(self._handle, milliseconds)
            if result == _WAIT_TIMEOUT:
                raise subprocess.TimeoutExpired(tuple(), timeout)
            if result != _WAIT_OBJECT_0:
                raise IsolationError("failed waiting for AppContainer process")
            exit_code = self.poll()
            if exit_code is None:
                raise IsolationError("AppContainer process remained active after wait")
            return exit_code

        def kill(self) -> None:
            if self.poll() is None and not _KERNEL32.TerminateProcess(self._handle, 1):
                raise IsolationError("failed to terminate AppContainer process")

        def close(self) -> None:
            thread_handle = getattr(self, "_thread_handle", None)
            if thread_handle:
                _KERNEL32.CloseHandle(thread_handle)
                del self._thread_handle
            if self._handle:
                _KERNEL32.CloseHandle(self._handle)
                self._handle = 0
            userenv = ctypes.WinDLL("userenv", use_last_error=True)
            userenv.DeleteAppContainerProfile.argtypes = [wintypes.LPCWSTR]
            userenv.DeleteAppContainerProfile.restype = ctypes.c_long
            userenv.DeleteAppContainerProfile(self._identity)

    def _sandbox_spec(read_only_paths: tuple[str, ...]) -> bytes:
        builder = flatbuffers.Builder(512)
        version = builder.CreateString("0.1.0")
        capabilities = builder.CreateString("")
        path_offsets = [builder.CreateString(path) for path in read_only_paths]
        builder.StartVector(4, len(path_offsets), 4)
        for offset in reversed(path_offsets):
            builder.PrependUOffsetTRelative(offset)
        read_only = builder.EndVector()
        # Public Windows SDK schema slots. Keep the deprecated integrity slot
        # because FlatBuffers field positions are wire-compatible contracts.
        builder.StartObject(13)
        builder.PrependUOffsetTRelativeSlot(0, version, 0)
        builder.PrependBoolSlot(1, True, False)
        builder.PrependBoolSlot(5, True, False)  # least_privilege
        builder.PrependUOffsetTRelativeSlot(6, capabilities, 0)
        builder.PrependUOffsetTRelativeSlot(8, read_only, 0)
        root = builder.EndObject()
        builder.Finish(root, file_identifier=b"SBOX")
        return bytes(builder.Output())

    class _JobBasicLimitInformation(ctypes.Structure):
        _fields_ = [
            ("PerProcessUserTimeLimit", _ULARGE_INTEGER),
            ("PerJobUserTimeLimit", _ULARGE_INTEGER),
            ("LimitFlags", _DWORD),
            ("MinimumWorkingSetSize", _SIZE_T),
            ("MaximumWorkingSetSize", _SIZE_T),
            ("ActiveProcessLimit", _DWORD),
            ("Affinity", ctypes.c_void_p),
            ("PriorityClass", _DWORD),
            ("SchedulingClass", _DWORD),
        ]

    class _JobExtendedLimitInformation(ctypes.Structure):
        _fields_ = [
            ("BasicLimitInformation", _JobBasicLimitInformation),
            ("IoInfo", ctypes.c_byte * 48),
            ("ProcessMemoryLimit", _SIZE_T),
            ("JobMemoryLimit", _SIZE_T),
            ("PeakProcessMemoryUsed", _SIZE_T),
            ("PeakJobMemoryUsed", _SIZE_T),
        ]

    class _JobBasicAccountingInformation(ctypes.Structure):
        _fields_ = [
            ("TotalUserTime", ctypes.c_longlong),
            ("TotalKernelTime", ctypes.c_longlong),
            ("ThisPeriodTotalUserTime", ctypes.c_longlong),
            ("ThisPeriodTotalKernelTime", ctypes.c_longlong),
            ("TotalPageFaultCount", _DWORD),
            ("TotalProcesses", _DWORD),
            ("ActiveProcesses", _DWORD),
            ("TotalTerminatedProcesses", _DWORD),
        ]

    class _ThreadEntry32(ctypes.Structure):
        _fields_ = [
            ("dwSize", wintypes.DWORD),
            ("cntUsage", wintypes.DWORD),
            ("th32ThreadID", wintypes.DWORD),
            ("th32OwnerProcessID", wintypes.DWORD),
            ("tpBasePri", wintypes.LONG),
            ("tpDeltaPri", wintypes.LONG),
            ("dwFlags", wintypes.DWORD),
        ]

    _KERNEL32.Thread32First.argtypes = [wintypes.HANDLE, ctypes.POINTER(_ThreadEntry32)]
    _KERNEL32.Thread32First.restype = wintypes.BOOL
    _KERNEL32.Thread32Next.argtypes = [wintypes.HANDLE, ctypes.POINTER(_ThreadEntry32)]
    _KERNEL32.Thread32Next.restype = wintypes.BOOL

    def _resume_suspended_process(process: object) -> None:
        process_id = getattr(process, "pid", None)
        if not isinstance(process_id, int) or process_id <= 0:
            raise IsolationError("suspended process id unavailable")
        snapshot = _KERNEL32.CreateToolhelp32Snapshot(_TH32CS_SNAPTHREAD, 0)
        if snapshot == _INVALID_HANDLE_VALUE:
            raise IsolationError("thread snapshot failed")
        thread_handle = None
        try:
            entry = _ThreadEntry32()
            entry.dwSize = ctypes.sizeof(entry)
            found = _KERNEL32.Thread32First(snapshot, ctypes.byref(entry))
            thread_id = None
            while found:
                if entry.th32OwnerProcessID == process_id:
                    thread_id = entry.th32ThreadID
                    break
                found = _KERNEL32.Thread32Next(snapshot, ctypes.byref(entry))
            if thread_id is None:
                raise IsolationError("suspended process thread unavailable")
            thread_handle = _KERNEL32.OpenThread(
                _THREAD_SUSPEND_RESUME,
                False,
                thread_id,
            )
            if not thread_handle:
                raise IsolationError("suspended process thread could not be opened")
            if _KERNEL32.ResumeThread(thread_handle) == 0xFFFFFFFF:
                raise IsolationError("failed to resume isolated process")
        finally:
            if thread_handle:
                _KERNEL32.CloseHandle(thread_handle)
            _KERNEL32.CloseHandle(snapshot)

    class _WindowsJobBinding:
        def __init__(
            self,
            handle: int,
            process: _WindowsSandboxProcess | None = None,
            *,
            cpu_time_seconds: float | None = None,
        ) -> None:
            self._handle = handle
            self._process = process
            self._monitor_stop = threading.Event()
            self._monitor = None
            if cpu_time_seconds is not None:
                cpu_ticks = int(cpu_time_seconds * 10_000_000)
                self._monitor = threading.Thread(
                    target=self._enforce_cpu_limit,
                    args=(cpu_ticks,),
                    daemon=True,
                )
                self._monitor.start()

        def _enforce_cpu_limit(self, cpu_ticks: int) -> None:
            while not self._monitor_stop.wait(0.01):
                accounting = _JobBasicAccountingInformation()
                returned = _DWORD()
                ok = _KERNEL32.QueryInformationJobObject(
                    self._handle,
                    1,
                    ctypes.byref(accounting),
                    ctypes.sizeof(accounting),
                    ctypes.byref(returned),
                )
                if not ok:
                    _KERNEL32.TerminateJobObject(self._handle, 1816)
                    return
                if accounting.TotalUserTime >= cpu_ticks:
                    _KERNEL32.TerminateJobObject(self._handle, 1816)
                    return
                if accounting.ActiveProcesses == 0 and accounting.TotalProcesses > 0:
                    return

        def close(self) -> None:
            self._monitor_stop.set()
            if self._monitor is not None:
                self._monitor.join(timeout=1)
                self._monitor = None
            if self._handle:
                _KERNEL32.CloseHandle(self._handle)
                self._handle = 0
            if self._process is not None:
                self._process.close()
                self._process = None

    class WindowsJobObjectBackend(ProcessIsolationBackend):
        """Apply CPU and memory ceilings with a Windows Job Object.

        Network denial is intentionally rejected here: a Job Object does not
        provide a network boundary.  A future firewall-backed backend must
        implement that control instead of silently weakening the policy.
        """

        def launch(
            self,
            argv: tuple[str, ...],
            *,
            working_directory: str,
            environment: dict[str, str],
            limits: IsolationLimits,
        ) -> tuple[object, IsolationBinding]:
            job = _KERNEL32.CreateJobObjectW(None, None)
            if not job:
                raise IsolationError("CreateJobObjectW failed")
            info = _JobExtendedLimitInformation()
            # PROCESS_TIME + JOB_TIME + PROCESS_MEMORY + KILL_ON_JOB_CLOSE.
            # The job-wide ceiling also covers descendant CPU consumption.
            cpu_ticks = int(limits.cpu_time_seconds * 10_000_000)
            info.BasicLimitInformation.LimitFlags = 0x2 | 0x4 | 0x100 | 0x2000
            info.BasicLimitInformation.PerProcessUserTimeLimit = cpu_ticks
            info.BasicLimitInformation.PerJobUserTimeLimit = cpu_ticks
            info.ProcessMemoryLimit = limits.memory_bytes
            configured = _KERNEL32.SetInformationJobObject(
                job,
                9,
                ctypes.byref(info),
                ctypes.sizeof(info),
            )
            if not configured:
                _KERNEL32.CloseHandle(job)
                raise IsolationError("failed to configure Windows Job Object")
            process = None
            try:
                if limits.network_mode == "deny":
                    process = self._launch_appcontainer(
                        argv,
                        working_directory=working_directory,
                        environment=environment,
                    )
                    handle = process._handle
                    if not _KERNEL32.AssignProcessToJobObject(job, handle):
                        raise IsolationError("failed to bind AppContainer to Job Object")
                    if _KERNEL32.ResumeThread(process._thread_handle) == 0xFFFFFFFF:
                        raise IsolationError("failed to resume AppContainer process")
                    _KERNEL32.CloseHandle(process._thread_handle)
                    del process._thread_handle
                    return process, _WindowsJobBinding(
                        job, process, cpu_time_seconds=limits.cpu_time_seconds
                    )
                process = subprocess.Popen(
                    list(argv),
                    shell=False,
                    cwd=working_directory,
                    env=environment,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    creationflags=_CREATE_SUSPENDED,
                )
                handle = getattr(process, "_handle", None)
                if not handle or not _KERNEL32.AssignProcessToJobObject(job, handle):
                    raise IsolationError("failed to assign suspended process to Job Object")
                _resume_suspended_process(process)
                return process, _WindowsJobBinding(
                    job, cpu_time_seconds=limits.cpu_time_seconds
                )
            except Exception:
                if process is not None:
                    process.kill()
                    process.wait(timeout=5)
                    close = getattr(process, "close", None)
                    if close is not None:
                        close()
                _KERNEL32.CloseHandle(job)
                raise

        @staticmethod
        def _launch_appcontainer(
            argv: tuple[str, ...], *, working_directory: str, environment: dict[str, str]
        ) -> _WindowsSandboxProcess:
            library = ctypes.WinDLL("processmodel.dll", use_last_error=True)
            create = library.Experimental_CreateProcessInSandbox
            create.argtypes = [
                wintypes.LPCWSTR, wintypes.LPWSTR, ctypes.c_void_p, ctypes.c_void_p,
                wintypes.BOOL, wintypes.DWORD, ctypes.c_void_p, wintypes.LPCWSTR,
                ctypes.POINTER(_StartupInfo), wintypes.LPCWSTR, ctypes.c_void_p,
                wintypes.DWORD, ctypes.POINTER(_ProcessInformation),
            ]
            create.restype = wintypes.BOOL
            executable = os.path.abspath(argv[0])
            read_only_paths = tuple(dict.fromkeys((os.path.dirname(executable), working_directory)))
            spec = _sandbox_spec(read_only_paths)
            spec_buffer = ctypes.create_string_buffer(spec)
            command_line = ctypes.create_unicode_buffer(subprocess.list2cmdline(argv))
            environment_text = "\0".join(
                f"{name}={value}" for name, value in sorted(environment.items())
            ) + "\0\0"
            environment_buffer = ctypes.create_unicode_buffer(environment_text)
            startup = _StartupInfo()
            startup.cb = ctypes.sizeof(startup)
            info = _ProcessInformation()
            identity = f"AISCP.{uuid.uuid4().hex}"
            created = create(
                executable, command_line, None, None, False,
                _CREATE_SUSPENDED | _CREATE_UNICODE_ENVIRONMENT,
                environment_buffer, working_directory, ctypes.byref(startup),
                identity, spec_buffer, len(spec),
                ctypes.byref(info),
            )
            if not created:
                raise IsolationError(
                    f"AppContainer launch failed with Windows error {ctypes.get_last_error()}"
                )
            process = _WindowsSandboxProcess(info.hProcess, info.dwProcessId, identity)
            process._thread_handle = info.hThread
            return process

        def apply(self, process: object, limits: IsolationLimits) -> IsolationBinding:
            if limits.network_mode == "deny":
                raise IsolationError("Windows Job Objects do not enforce network denial")
            pid = getattr(process, "_handle", None)
            if not pid:
                raise IsolationError("process handle unavailable")
            job = _KERNEL32.CreateJobObjectW(None, None)
            if not job:
                raise IsolationError("CreateJobObjectW failed")
            info = _JobExtendedLimitInformation()
            cpu_ticks = int(limits.cpu_time_seconds * 10_000_000)
            info.BasicLimitInformation.LimitFlags = 0x2 | 0x4 | 0x100 | 0x2000
            info.BasicLimitInformation.PerProcessUserTimeLimit = cpu_ticks
            info.BasicLimitInformation.PerJobUserTimeLimit = cpu_ticks
            info.ProcessMemoryLimit = limits.memory_bytes
            ok = _KERNEL32.SetInformationJobObject(
                job,
                9,
                ctypes.byref(info),
                ctypes.sizeof(info),
            )
            if not ok or not _KERNEL32.AssignProcessToJobObject(job, pid):
                _KERNEL32.CloseHandle(job)
                raise IsolationError("failed to configure Windows Job Object")
            return _WindowsJobBinding(job, cpu_time_seconds=limits.cpu_time_seconds)
else:
    class WindowsJobObjectBackend(ProcessIsolationBackend):
        def launch(
            self,
            argv: tuple[str, ...],
            *,
            working_directory: str,
            environment: dict[str, str],
            limits: IsolationLimits,
        ) -> tuple[object, IsolationBinding]:
            del argv, working_directory, environment
            if limits.network_mode == "deny":
                raise IsolationError("Windows Job Object backend unavailable on this host")
            raise IsolationError("pre-launch OS isolation backend unavailable")

        def apply(self, process: object, limits: IsolationLimits) -> IsolationBinding:
            del process
            if limits.require_os_enforcement or limits.network_mode == "deny":
                raise IsolationError("Windows Job Object backend unavailable on this host")
            return _NoopBinding()


def default_isolation_backend() -> ProcessIsolationBackend:
    return WindowsJobObjectBackend() if os.name == "nt" else UnavailableIsolationBackend()
