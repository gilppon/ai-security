"""Replaceable OS isolation backends for the safe process executor.

The policy layer remains deterministic; this module only applies already
authorized limits to a spawned process.  A backend must fail closed when a
requested control cannot be enforced by the host OS.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
import ctypes
import os
import subprocess
from typing import Literal, Protocol

from pydantic import BaseModel, ConfigDict, Field


_CREATE_SUSPENDED = 0x00000004


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
    _DWORD = ctypes.c_uint32
    _SIZE_T = ctypes.c_size_t
    _ULARGE_INTEGER = ctypes.c_ulonglong

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

    class _WindowsJobBinding:
        def __init__(self, handle: int) -> None:
            self._handle = handle

        def close(self) -> None:
            if self._handle:
                ctypes.windll.kernel32.CloseHandle(self._handle)
                self._handle = 0

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
            if limits.network_mode == "deny":
                raise IsolationError("Windows Job Objects do not enforce network denial")
            kernel32 = ctypes.windll.kernel32
            kernel32.CreateJobObjectW.restype = ctypes.c_void_p
            kernel32.SetInformationJobObject.argtypes = [ctypes.c_void_p, _DWORD, ctypes.c_void_p, _DWORD]
            kernel32.AssignProcessToJobObject.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
            kernel32.ResumeThread.argtypes = [ctypes.c_void_p]
            kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
            job = kernel32.CreateJobObjectW(None, None)
            if not job:
                raise IsolationError("CreateJobObjectW failed")
            info = _JobExtendedLimitInformation()
            # PROCESS_TIME + PROCESS_MEMORY + KILL_ON_JOB_CLOSE.  Do not set
            # JOB_MEMORY/JOB_TIME flags without populating their fields.
            info.BasicLimitInformation.LimitFlags = 0x2 | 0x100 | 0x2000
            info.BasicLimitInformation.PerProcessUserTimeLimit = int(limits.cpu_time_seconds * 10_000_000)
            info.ProcessMemoryLimit = limits.memory_bytes
            configured = kernel32.SetInformationJobObject(
                job,
                9,
                ctypes.byref(info),
                ctypes.sizeof(info),
            )
            if not configured:
                kernel32.CloseHandle(job)
                raise IsolationError("failed to configure Windows Job Object")
            process = None
            try:
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
                if not handle or not kernel32.AssignProcessToJobObject(job, handle):
                    raise IsolationError("failed to assign suspended process to Job Object")
                thread = getattr(process, "_thread", None)
                if not thread or kernel32.ResumeThread(thread) == 0xFFFFFFFF:
                    raise IsolationError("failed to resume isolated process")
                return process, _WindowsJobBinding(job)
            except Exception:
                if process is not None:
                    process.kill()
                    process.wait(timeout=5)
                kernel32.CloseHandle(job)
                raise

        def apply(self, process: object, limits: IsolationLimits) -> IsolationBinding:
            if limits.network_mode == "deny":
                raise IsolationError("Windows Job Objects do not enforce network denial")
            pid = getattr(process, "_handle", None)
            if not pid:
                raise IsolationError("process handle unavailable")
            kernel32 = ctypes.windll.kernel32
            kernel32.CreateJobObjectW.restype = ctypes.c_void_p
            kernel32.SetInformationJobObject.argtypes = [ctypes.c_void_p, _DWORD, ctypes.c_void_p, _DWORD]
            kernel32.AssignProcessToJobObject.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
            kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
            job = kernel32.CreateJobObjectW(None, None)
            if not job:
                raise IsolationError("CreateJobObjectW failed")
            info = _JobExtendedLimitInformation()
            info.BasicLimitInformation.LimitFlags = 0x2 | 0x100 | 0x2000
            info.BasicLimitInformation.PerProcessUserTimeLimit = int(limits.cpu_time_seconds * 10_000_000)
            info.ProcessMemoryLimit = limits.memory_bytes
            ok = kernel32.SetInformationJobObject(
                job,
                9,
                ctypes.byref(info),
                ctypes.sizeof(info),
            )
            if not ok or not kernel32.AssignProcessToJobObject(job, pid):
                kernel32.CloseHandle(job)
                raise IsolationError("failed to configure Windows Job Object")
            return _WindowsJobBinding(job)
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
