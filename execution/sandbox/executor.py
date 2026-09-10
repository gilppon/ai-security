from hashlib import sha256
import os
import subprocess
import threading
import time
from typing import BinaryIO

from core.decisions.actions import DecisionAction
from core.decisions.models import SecurityDecision
from core.decisions.reasons import ReasonCode
from core.events.factory import SecurityEventFactory
from core.events.types import TrustLevel
from core.fingerprints import fingerprint_text
from execution.sandbox.models import ProcessExecutionResult
from execution.sandbox.limits import (
    IsolationError,
    IsolationLimits,
    ProcessIsolationBackend,
    default_isolation_backend,
)
from resource_security.process.firewall import ProcessFirewall
from telemetry.audit import StructuredAuditLogger


class SafeExecutor:
    def __init__(
        self,
        process_firewall: ProcessFirewall,
        *,
        audit_logger: StructuredAuditLogger | None = None,
        event_factory: SecurityEventFactory | None = None,
        isolation_backend: ProcessIsolationBackend | None = None,
        require_os_isolation: bool = False,
        require_network_isolation: bool = False,
    ) -> None:
        self._process_firewall = process_firewall
        self._audit_logger = audit_logger or StructuredAuditLogger()
        self._event_factory = event_factory or SecurityEventFactory()
        self._isolation_backend = isolation_backend or default_isolation_backend()
        self._require_os_isolation = require_os_isolation
        self._require_network_isolation = require_network_isolation

    def execute(self, capability: str) -> ProcessExecutionResult:
        capability_is_valid = isinstance(capability, str) and 1 <= len(capability) <= 512
        event = self._event_factory.create(
            event_type="process.execute",
            source="safe_executor",
            action="execute",
            target="process",
            resource_type="process_capability",
            trust_level=TrustLevel.TRUSTED,
            data={
                "capability_fingerprint": fingerprint_text(
                    capability if capability_is_valid else "invalid-capability"
                )
            },
        )
        if capability_is_valid:
            spec, failure = self._process_firewall.consume(capability)
        else:
            spec, failure = None, ReasonCode.PROCESS_CAPABILITY_INVALID
        if spec is None:
            decision = self._decision(DecisionAction.DENY, failure or ReasonCode.UNKNOWN_SECURITY_STATE, 100)
            self._audit_logger.record(event, decision)
            return ProcessExecutionResult(event_id=event.event_id, decision=decision)

        try:
            exit_code, stdout, stderr, stdout_count, stderr_count, limit_hit, timed_out = (
                self._run_bounded(
                    spec.argv,
                    str(spec.working_directory),
                    spec.timeout_seconds,
                    spec.max_output_bytes,
                    isolation_backend=(
                        self._isolation_backend
                        if self._require_os_isolation or self._require_network_isolation
                        else None
                    ),
                    isolation_limits=IsolationLimits(
                        cpu_time_seconds=min(spec.timeout_seconds, 300.0),
                        network_mode="deny" if self._require_network_isolation else "inherit",
                        require_os_enforcement=self._require_os_isolation,
                    ),
                )
            )
            if timed_out:
                decision = self._decision(DecisionAction.TERMINATE, ReasonCode.PROCESS_TIMEOUT, 100)
            elif limit_hit:
                decision = self._decision(DecisionAction.TERMINATE, ReasonCode.PROCESS_OUTPUT_LIMIT, 100)
            elif exit_code != 0:
                decision = self._decision(DecisionAction.LOG, ReasonCode.PROCESS_NONZERO_EXIT, 20)
            else:
                decision = self._decision(DecisionAction.ALLOW, ReasonCode.PROCESS_EXECUTED, 0)
        except IsolationError as exc:
            exit_code = None
            stdout = stderr = b""
            stdout_count = stderr_count = 0
            reason = (
                ReasonCode.PROCESS_NETWORK_ISOLATION_UNAVAILABLE
                if "network" in str(exc).lower()
                else ReasonCode.PROCESS_ISOLATION_UNAVAILABLE
                if "unavailable" in str(exc).lower()
                else ReasonCode.PROCESS_ISOLATION_FAILED
            )
            failure_metadata = {"isolation_failure_stage": exc.stage}
            if exc.os_error_code is not None:
                failure_metadata["isolation_error_code"] = str(exc.os_error_code)
            decision = self._decision(
                DecisionAction.DENY,
                reason,
                100,
                metadata=failure_metadata,
            )
        except Exception:
            exit_code = None
            stdout = stderr = b""
            stdout_count = stderr_count = 0
            decision = self._decision(DecisionAction.DENY, ReasonCode.UNKNOWN_SECURITY_STATE, 100)

        self._audit_logger.record(event, decision)
        return ProcessExecutionResult(
            event_id=event.event_id,
            authorization_event_id=spec.authorization_event_id,
            decision=decision,
            exit_code=exit_code,
            stdout_bytes=stdout_count,
            stderr_bytes=stderr_count,
            stdout_fingerprint=sha256(stdout).hexdigest() if stdout_count else None,
            stderr_fingerprint=sha256(stderr).hexdigest() if stderr_count else None,
        )

    @staticmethod
    def _run_bounded(
        argv: tuple[str, ...],
        working_directory: str,
        timeout_seconds: float,
        max_output_bytes: int,
        *,
        isolation_backend: ProcessIsolationBackend | None = None,
        isolation_limits: IsolationLimits | None = None,
    ) -> tuple[int, bytes, bytes, int, int, bool, bool]:
        requested_limits = isolation_limits or IsolationLimits()
        requires_prelaunch_isolation = (
            requested_limits.require_os_enforcement
            or requested_limits.network_mode == "deny"
        )
        if isolation_backend is not None and requires_prelaunch_isolation:
            process, binding = isolation_backend.launch(
                argv,
                working_directory=working_directory,
                environment=_minimal_environment(),
                limits=requested_limits,
            )
        else:
            process = subprocess.Popen(
                list(argv),
                shell=False,
                cwd=working_directory,
                env=_minimal_environment(),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            binding = None
        try:
            if isolation_backend is not None and not requires_prelaunch_isolation:
                binding = isolation_backend.apply(process, requested_limits)
        except Exception:
            process.kill()
            process.wait(timeout=5)
            raise
        if process.stdout is None or process.stderr is None:
            process.kill()
            raise RuntimeError("process pipes unavailable")

        lock = threading.Lock()
        overflow = threading.Event()
        buffers = {"stdout": bytearray(), "stderr": bytearray()}
        counts = {"stdout": 0, "stderr": 0}

        def collect(name: str, pipe: BinaryIO) -> None:
            while True:
                chunk = pipe.read(4096)
                if not chunk:
                    return
                with lock:
                    counts[name] += len(chunk)
                    stored = len(buffers["stdout"]) + len(buffers["stderr"])
                    room = max(0, max_output_bytes - stored)
                    buffers[name].extend(chunk[:room])
                    if len(chunk) > room:
                        overflow.set()
                        return

        readers = (
            threading.Thread(target=collect, args=("stdout", process.stdout), daemon=True),
            threading.Thread(target=collect, args=("stderr", process.stderr), daemon=True),
        )
        for reader in readers:
            reader.start()

        deadline = time.monotonic() + timeout_seconds
        timed_out = False
        while process.poll() is None:
            if overflow.is_set():
                process.kill()
                break
            if time.monotonic() >= deadline:
                timed_out = True
                process.kill()
                break
            time.sleep(0.01)
        try:
            process.wait(timeout=5)
            for reader in readers:
                reader.join(timeout=5)
            return (
                process.returncode,
                bytes(buffers["stdout"]),
                bytes(buffers["stderr"]),
                counts["stdout"],
                counts["stderr"],
                overflow.is_set(),
                timed_out,
            )
        finally:
            if binding is not None:
                binding.close()

    @staticmethod
    def _decision(
        action: DecisionAction,
        reason: ReasonCode,
        risk_score: int,
        *,
        metadata: dict[str, str] | None = None,
    ) -> SecurityDecision:
        return SecurityDecision(
            decision=action,
            risk_score=risk_score,
            reason_codes=(reason,),
            metadata=metadata or {},
        )


def _minimal_environment() -> dict[str, str]:
    # LOCALAPPDATA is required by the Windows AppContainer profile engine.
    # Authentication, cloud, and developer-tool variables remain excluded.
    allowed = ("LANG", "LC_ALL", "LOCALAPPDATA", "SYSTEMROOT", "WINDIR")
    return {name: os.environ[name] for name in allowed if name in os.environ}
