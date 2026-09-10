import json
from io import StringIO

from app.cli import CLIApplication
from core.decisions.actions import DecisionAction
from policy.lifecycle import PolicyBundleRegistry, parse_policy_bundle
from policy.runtime import ActivePolicyDetector
from input_security.prompt.models import MAX_PROMPT_LENGTH
from telemetry.audit import InMemoryAuditSink, StructuredAuditLogger


def run_cli(
    application: CLIApplication,
    arguments: tuple[str, ...],
    raw: str,
) -> tuple[int, dict[str, object]]:
    stdout = StringIO()
    exit_code = application.run(
        arguments,
        stdin=StringIO(raw),
        stdout=stdout,
    )
    return exit_code, json.loads(stdout.getvalue())


def test_cli_prompt_scan_reads_content_from_stdin() -> None:
    exit_code, result = run_cli(
        CLIApplication(),
        ("scan-prompt",),
        "Summarize this project status",
    )

    assert exit_code == 0
    assert result["decision"]["decision"] == "ALLOW"
    assert "Summarize this project status" not in json.dumps(result)


def test_cli_output_scan_blocks_secret_without_releasing_it() -> None:
    raw_secret = "Credential: api_key=AbCDef0123456789xyzXYZ"
    sink = InMemoryAuditSink()
    exit_code, result = run_cli(
        CLIApplication(audit_logger=StructuredAuditLogger(sink)),
        ("scan-output",),
        raw_secret,
    )

    assert exit_code == 2
    assert result["decision"]["decision"] == "DENY"
    assert result["released_output"] is None
    assert raw_secret not in json.dumps(result)
    assert raw_secret not in "".join(sink.records)


def test_cli_rejects_oversized_input_and_audits_without_raw_content() -> None:
    raw = "x" * (MAX_PROMPT_LENGTH + 1)
    sink = InMemoryAuditSink()
    exit_code, result = run_cli(
        CLIApplication(audit_logger=StructuredAuditLogger(sink)),
        ("scan-prompt",),
        raw,
    )

    assert exit_code == 2
    assert result["decision"]["reason_codes"] == ["CLI_INPUT_INVALID"]
    assert len(sink.records) == 1
    assert raw not in json.dumps(result)
    assert raw not in sink.records[0]


def test_cli_invalid_command_fails_closed_with_structured_reason() -> None:
    sink = InMemoryAuditSink()
    exit_code, result = run_cli(
        CLIApplication(audit_logger=StructuredAuditLogger(sink)),
        ("unknown-command",),
        "ignored",
    )

    assert exit_code == 2
    assert result["decision"]["decision"] == "DENY"
    assert result["decision"]["reason_codes"] == ["CLI_INPUT_INVALID"]
    assert len(sink.records) == 1


def test_cli_applies_active_policy_rules() -> None:
    source = """
id: ASEC-POLICY-CLI-DENY
title: Deny CLI prompt scans
category: core
severity: critical
when:
  event_type: prompt.scan
match:
  source: user
risk:
  score: 100
actions: [deny, audit]
"""
    registry = PolicyBundleRegistry()
    assert registry.publish(parse_policy_bundle("cli-policy", 1, source)).bundle is not None

    exit_code, result = run_cli(
        CLIApplication(policy_detector=ActivePolicyDetector(registry)),
        ("scan-prompt",),
        "Hello",
    )

    assert exit_code == 2
    assert result["decision"]["decision"] == DecisionAction.DENY.value
    assert "ASEC-POLICY-CLI-DENY" in result["decision"]["matched_rules"]
