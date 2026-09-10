from collections.abc import Callable
from pathlib import Path
import os
import secrets
import threading
import time

from core.context.models import SecurityContext
from core.contracts import DetectionEngineContract
from core.decisions.actions import DecisionAction
from core.decisions.models import SecurityDecision
from core.decisions.reasons import ReasonCode
from core.events.factory import SecurityEventFactory
from core.events.models import SecurityEvent
from core.events.types import TrustLevel
from core.fingerprints import fingerprint_text
from core.risk.engine import RiskEngine
from detection.models import DetectionFinding, RuleAction, Severity
from policy.engine import PolicyEngine
from policy.runtime import decide_with_active_policy
from resource_security.contracts import FilesystemAuthorizer
from resource_security.filesystem.models import FilesystemAuthorizationRequest, FilesystemOperation
from resource_security.process.models import (
    AuthorizedProcessSpec,
    ProcessAuthorizationRequest,
    ProcessAuthorizationResult,
    ProcessGrant,
)
from telemetry.audit import StructuredAuditLogger


_DENIED_EXECUTABLES = {
    "bash", "cmd", "cmd.exe", "dash", "fish", "ksh", "powershell", "powershell.exe",
    "pwsh", "pwsh.exe", "sh", "wsl", "wsl.exe", "zsh",
}
_DENIED_ARGUMENTS = {"-c", "-command", "-encodedcommand", "/c", "/k"}
_SHELL_TOKENS = {"&&", "||", "|", ">", ">>", "<", ";"}


class ProcessFirewall:
    def __init__(
        self,
        grants: tuple[ProcessGrant, ...] = (),
        *,
        filesystem_firewall: FilesystemAuthorizer | None = None,
        capability_ttl_seconds: float = 30.0,
        clock: Callable[[], float] = time.monotonic,
        policy_detector: DetectionEngineContract | None = None,
        risk_engine: RiskEngine | None = None,
        policy_engine: PolicyEngine | None = None,
        audit_logger: StructuredAuditLogger | None = None,
        event_factory: SecurityEventFactory | None = None,
    ) -> None:
        if not 0.1 <= capability_ttl_seconds <= 300:
            raise ValueError("capability TTL must be between 0.1 and 300 seconds")
        self._grants = tuple(self._normalize_grant(grant) for grant in grants)
        self._filesystem_firewall = filesystem_firewall
        self._capability_ttl_seconds = capability_ttl_seconds
        self._clock = clock
        self._capabilities: dict[str, AuthorizedProcessSpec] = {}
        self._used_capability_fingerprints: set[str] = set()
        self._capability_lock = threading.Lock()
        self._policy_detector = policy_detector
        self._risk_engine = risk_engine or RiskEngine()
        self._policy_engine = policy_engine or PolicyEngine()
        self._audit_logger = audit_logger or StructuredAuditLogger()
        self._event_factory = event_factory or SecurityEventFactory()

    def authorize(self, request: ProcessAuthorizationRequest) -> ProcessAuthorizationResult:
        event = self._event_factory.create(
            event_type="process.authorize",
            source="resource_firewall",
            action="authorize",
            target="process",
            resource_type="process",
            trust_level=TrustLevel.TRUSTED,
            session_id=request.session_id,
            data={
                "executable_fingerprint": fingerprint_text(request.argv[0]),
                "argument_count": len(request.argv) - 1,
                "working_directory_fingerprint": fingerprint_text(request.working_directory),
            },
        )
        capability: str | None = None
        try:
            finding, spec = self._validate(event.event_id, request)
            decision = self._decide(event, finding)
            if decision.decision is DecisionAction.ALLOW and spec is not None:
                capability = secrets.token_urlsafe(32)
                with self._capability_lock:
                    self._capabilities[capability] = spec
        except Exception:
            decision = SecurityDecision(
                decision=DecisionAction.DENY,
                risk_score=100,
                reason_codes=(ReasonCode.UNKNOWN_SECURITY_STATE,),
            )
        self._audit_logger.record(event, decision)
        return ProcessAuthorizationResult(event_id=event.event_id, decision=decision, capability=capability)

    def consume(self, capability: str) -> tuple[AuthorizedProcessSpec | None, ReasonCode | None]:
        fingerprint = fingerprint_text(capability)
        with self._capability_lock:
            if fingerprint in self._used_capability_fingerprints:
                return None, ReasonCode.PROCESS_CAPABILITY_REPLAYED
            spec = self._capabilities.pop(capability, None)
            if spec is None:
                return None, ReasonCode.PROCESS_CAPABILITY_INVALID
            self._used_capability_fingerprints.add(fingerprint)
        if self._clock() > spec.expires_at:
            return None, ReasonCode.PROCESS_CAPABILITY_EXPIRED
        return spec, None

    def _validate(
        self,
        event_id: str,
        request: ProcessAuthorizationRequest,
    ) -> tuple[DetectionFinding, AuthorizedProcessSpec | None]:
        requested_executable = Path(request.argv[0]).resolve(strict=False)
        if requested_executable.name.casefold() in _DENIED_EXECUTABLES:
            return self._finding("ASEC-PROC-SHELL-001", ReasonCode.PROCESS_EXECUTABLE_DENIED, True), None
        if any(arg.casefold() in _DENIED_ARGUMENTS or arg in _SHELL_TOKENS for arg in request.argv[1:]):
            return self._finding("ASEC-PROC-ARGUMENT-001", ReasonCode.PROCESS_ARGUMENT_DENIED, True), None
        grant = next((item for item in self._grants if item.executable == requested_executable), None)
        if grant is None:
            return self._finding("ASEC-PROC-EXECUTABLE-001", ReasonCode.PROCESS_EXECUTABLE_DENIED, True), None
        if request.argv[1:1 + len(grant.argument_prefix)] != grant.argument_prefix:
            return self._finding("ASEC-PROC-PREFIX-001", ReasonCode.PROCESS_ARGUMENT_DENIED, True), None
        expected_positions = set(range(1, len(grant.argument_prefix) + 1)) | set(grant.path_argument_indices)
        if set(range(1, len(request.argv))) != expected_positions:
            return self._finding("ASEC-PROC-SHAPE-001", ReasonCode.PROCESS_ARGUMENT_DENIED, True), None
        if request.timeout_seconds > grant.max_timeout_seconds:
            return self._finding("ASEC-PROC-TIMEOUT-001", ReasonCode.PROCESS_ARGUMENT_DENIED, True), None
        if self._filesystem_firewall is None:
            return self._finding("ASEC-PROC-FS-MISSING-001", ReasonCode.RESOURCE_FIREWALL_UNAVAILABLE, True), None

        cwd_result = self._filesystem_firewall.authorize(FilesystemAuthorizationRequest(
            path=request.working_directory,
            operation=FilesystemOperation.LIST,
            session_id=request.session_id,
        ))
        if cwd_result.decision.decision is not DecisionAction.ALLOW or cwd_result.normalized_resource is None:
            return self._finding(
                "ASEC-PROC-CWD-001", ReasonCode.PROCESS_WORKING_DIRECTORY_DENIED, True
            ), None
        resolved_cwd = Path(cwd_result.normalized_resource)
        if not resolved_cwd.is_dir() or not any(
            resolved_cwd.is_relative_to(root) for root in grant.working_roots
        ):
            return self._finding(
                "ASEC-PROC-CWD-GRANT-001", ReasonCode.PROCESS_WORKING_DIRECTORY_DENIED, True
            ), None

        authorized_argv = [str(grant.executable), *request.argv[1:]]
        for index in grant.path_argument_indices:
            if index >= len(request.argv):
                return self._finding(
                    "ASEC-PROC-PATH-ARGUMENT-001", ReasonCode.PROCESS_ARGUMENT_DENIED, True
                ), None
            path_result = self._filesystem_firewall.authorize(FilesystemAuthorizationRequest(
                path=request.argv[index],
                operation=FilesystemOperation.READ,
                session_id=request.session_id,
            ))
            if (
                path_result.decision.decision is not DecisionAction.ALLOW
                or path_result.normalized_resource is None
                or not Path(path_result.normalized_resource).is_file()
            ):
                return self._finding(
                    "ASEC-PROC-PATH-DENIED-001", ReasonCode.PROCESS_ARGUMENT_DENIED, True
                ), None
            authorized_argv[index] = path_result.normalized_resource

        spec = AuthorizedProcessSpec(
            authorization_event_id=event_id,
            executable=grant.executable,
            argv=tuple(authorized_argv),
            working_directory=resolved_cwd,
            timeout_seconds=request.timeout_seconds,
            max_output_bytes=grant.max_output_bytes,
            session_id=request.session_id,
            expires_at=self._clock() + self._capability_ttl_seconds,
        )
        return self._finding("ASEC-PROC-GRANT-001", ReasonCode.PROCESS_AUTHORIZED, False), spec

    @staticmethod
    def _normalize_grant(grant: ProcessGrant) -> ProcessGrant:
        executable = grant.executable.resolve(strict=False)
        if not executable.is_file() or not os.access(executable, os.X_OK):
            raise ValueError("process executable grant must resolve to an executable file")
        return ProcessGrant(
            executable=executable,
            argument_prefix=grant.argument_prefix,
            working_roots=tuple(root.resolve(strict=False) for root in grant.working_roots),
            path_argument_indices=grant.path_argument_indices,
            max_timeout_seconds=grant.max_timeout_seconds,
            max_output_bytes=grant.max_output_bytes,
        )

    def _decide(self, event: SecurityEvent, finding: DetectionFinding) -> SecurityDecision:
        context = SecurityContext(user_trust=TrustLevel.TRUSTED, agent_trust=TrustLevel.TRUSTED)
        return decide_with_active_policy(
            event=event,
            context=context,
            findings=(finding,),
            risk_engine=self._risk_engine,
            policy_engine=self._policy_engine,
            policy_detector=self._policy_detector,
        )

    @staticmethod
    def _finding(rule_id: str, reason: ReasonCode, deny: bool) -> DetectionFinding:
        return DetectionFinding(
            rule_id=rule_id,
            severity=Severity.CRITICAL if deny else Severity.INFO,
            risk_score=100 if deny else 0,
            actions=(RuleAction.DENY if deny else RuleAction.ALLOW, RuleAction.AUDIT),
            reason_codes=(reason.value,),
        )
