import argparse
import json
import sys
from collections.abc import Sequence
from typing import TextIO

from pydantic import BaseModel, ConfigDict, ValidationError

from content_security.firewall import ContentFirewall
from content_security.models import (
    MAX_CONTENT_LENGTH,
    ContentScanRequest,
    ContentSourceType,
    ContentType,
)
from core.decisions.actions import DecisionAction
from core.decisions.models import SecurityDecision
from core.decisions.reasons import ReasonCode
from core.events.factory import SecurityEventFactory
from core.events.types import TrustLevel
from core.contracts import DetectionEngineContract
from input_security.prompt.firewall import PromptFirewall
from input_security.prompt.models import MAX_PROMPT_LENGTH, PromptScanRequest
from output_security.guard import OutputGuard
from output_security.models import MAX_OUTPUT_LENGTH, OutputScanRequest
from telemetry.audit import StructuredAuditLogger
from app.config import Settings
from app.policy_startup import activate_policy_or_raise, activation_service_from_settings
from policy.lifecycle import PolicyBundleRegistry
from policy.runtime import ActivePolicyDetector


_SUCCESS_ACTIONS = frozenset({
    DecisionAction.ALLOW,
    DecisionAction.LOG,
    DecisionAction.SANITIZE,
})


class CLIErrorResult(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    event_id: str
    decision: SecurityDecision


class CLIUsageError(ValueError):
    pass


class _ArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise CLIUsageError(message)


class CLIApplication:
    def __init__(
        self,
        *,
        prompt_firewall: PromptFirewall | None = None,
        content_firewall: ContentFirewall | None = None,
        output_guard: OutputGuard | None = None,
        policy_detector: DetectionEngineContract | None = None,
        audit_logger: StructuredAuditLogger | None = None,
        event_factory: SecurityEventFactory | None = None,
    ) -> None:
        self._prompt_firewall = prompt_firewall or PromptFirewall(policy_detector=policy_detector)
        self._content_firewall = content_firewall or ContentFirewall(policy_detector=policy_detector)
        self._output_guard = output_guard or OutputGuard(policy_detector=policy_detector)
        self._audit_logger = audit_logger or StructuredAuditLogger()
        self._event_factory = event_factory or SecurityEventFactory()

    def run(
        self,
        argv: Sequence[str],
        *,
        stdin: TextIO,
        stdout: TextIO,
    ) -> int:
        try:
            arguments = _parser().parse_args(tuple(argv))
        except CLIUsageError:
            return self._emit_error(
                stdout,
                action="invalid",
                reason=ReasonCode.CLI_INPUT_INVALID,
                input_length=0,
            )

        limit = {
            "scan-prompt": MAX_PROMPT_LENGTH,
            "scan-content": MAX_CONTENT_LENGTH,
            "scan-output": MAX_OUTPUT_LENGTH,
        }[arguments.command]
        raw = stdin.read(limit + 1)
        if len(raw) > limit:
            return self._emit_error(
                stdout,
                action=arguments.command,
                reason=ReasonCode.CLI_INPUT_INVALID,
                input_length=len(raw),
            )

        try:
            result = self._dispatch(arguments, raw)
        except ValidationError:
            return self._emit_error(
                stdout,
                action=arguments.command,
                reason=ReasonCode.CLI_INPUT_INVALID,
                input_length=len(raw),
            )
        except Exception:
            return self._emit_error(
                stdout,
                action=arguments.command,
                reason=ReasonCode.CLI_OPERATION_FAILED,
                input_length=len(raw),
            )

        _write_json(stdout, result)
        return 0 if result.decision.decision in _SUCCESS_ACTIONS else 2

    def _dispatch(self, arguments: argparse.Namespace, raw: str) -> BaseModel:
        if arguments.command == "scan-prompt":
            return self._prompt_firewall.scan(PromptScanRequest(
                prompt=raw,
                session_id=arguments.session_id,
            ))
        if arguments.command == "scan-content":
            return self._content_firewall.scan(ContentScanRequest(
                content=raw,
                content_type=ContentType(arguments.content_type),
                source_type=ContentSourceType(arguments.source_type),
                session_id=arguments.session_id,
            ))
        return self._output_guard.scan(OutputScanRequest(
            output=raw,
            session_id=arguments.session_id,
        ))

    def _emit_error(
        self,
        stdout: TextIO,
        *,
        action: str,
        reason: ReasonCode,
        input_length: int,
    ) -> int:
        event = self._event_factory.create(
            event_type="cli.input.reject",
            source="cli",
            action=action,
            target="security_control_plane",
            resource_type="stdin",
            trust_level=TrustLevel.UNTRUSTED,
            data={
                "input_length": input_length,
                "reason_code": reason.value,
            },
        )
        decision = SecurityDecision(
            decision=DecisionAction.DENY,
            risk_score=100,
            reason_codes=(reason,),
        )
        self._audit_logger.record(event, decision)
        _write_json(stdout, CLIErrorResult(event_id=event.event_id, decision=decision))
        return 2


def _parser() -> _ArgumentParser:
    parser = _ArgumentParser(prog="python -m app", add_help=True)
    commands = parser.add_subparsers(dest="command", required=True)

    prompt = commands.add_parser("scan-prompt", help="scan prompt read from stdin")
    _add_session_argument(prompt)

    content = commands.add_parser("scan-content", help="scan external content read from stdin")
    _add_session_argument(content)
    content.add_argument(
        "--content-type",
        choices=tuple(item.value for item in ContentType),
        default=ContentType.PLAIN_TEXT.value,
    )
    content.add_argument(
        "--source-type",
        choices=tuple(item.value for item in ContentSourceType),
        default=ContentSourceType.UNKNOWN.value,
    )

    output = commands.add_parser("scan-output", help="scan LLM output read from stdin")
    _add_session_argument(output)
    return parser


def _add_session_argument(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--session-id", default=None)


def _write_json(stdout: TextIO, value: BaseModel) -> None:
    serialized = json.dumps(
        value.model_dump(mode="json"),
        sort_keys=True,
        separators=(",", ":"),
    )
    stdout.write(serialized)
    stdout.write("\n")


def main(argv: Sequence[str] | None = None) -> int:
    settings = Settings.from_environment()
    activation_service = activation_service_from_settings(settings)
    registry = activation_service.registry if activation_service else PolicyBundleRegistry()
    activate_policy_or_raise(settings, activation_service)
    return CLIApplication(policy_detector=ActivePolicyDetector(registry)).run(
        tuple(sys.argv[1:] if argv is None else argv),
        stdin=sys.stdin,
        stdout=sys.stdout,
    )
