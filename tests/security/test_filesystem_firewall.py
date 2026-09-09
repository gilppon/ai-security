import os
from pathlib import Path

import pytest

from core.decisions.actions import DecisionAction
from core.decisions.reasons import ReasonCode
from resource_security.filesystem.firewall import FilesystemFirewall
from resource_security.filesystem.models import (
    FilesystemAuthorizationRequest,
    FilesystemGrant,
    FilesystemOperation,
)
from telemetry.audit import InMemoryAuditSink, StructuredAuditLogger


def make_firewall(root: Path) -> tuple[FilesystemFirewall, InMemoryAuditSink]:
    sink = InMemoryAuditSink()
    grant = FilesystemGrant(
        root=root,
        operations=frozenset({FilesystemOperation.READ, FilesystemOperation.WRITE}),
    )
    return FilesystemFirewall(
        (grant,),
        audit_logger=StructuredAuditLogger(sink),
    ), sink


def authorize(
    firewall: FilesystemFirewall,
    path: str,
    operation: FilesystemOperation = FilesystemOperation.READ,
):
    return firewall.authorize(FilesystemAuthorizationRequest(path=path, operation=operation))


def test_workspace_read_and_write_are_allowed(tmp_path: Path) -> None:
    firewall, sink = make_firewall(tmp_path)

    read = authorize(firewall, "docs/readme.md")
    write = authorize(firewall, str(tmp_path / "output.txt"), FilesystemOperation.WRITE)

    assert read.decision.decision is DecisionAction.ALLOW
    assert write.decision.decision is DecisionAction.ALLOW
    assert Path(read.normalized_resource or "").is_relative_to(tmp_path.resolve())
    assert len(sink.records) == 2


def test_path_traversal_is_denied_after_resolution(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    firewall, _ = make_firewall(workspace)

    result = authorize(firewall, "../outside.txt")

    assert result.decision.decision is DecisionAction.DENY
    assert ReasonCode.PATH_OUTSIDE_ALLOWED_ROOT in result.decision.reason_codes
    assert result.normalized_resource is None


@pytest.mark.parametrize(
    "relative_path",
    [
        ".ssh/id_rsa",
        ".aws/credentials",
        ".env",
        ".env.production",
        "certs/private.pem",
        "certs/private.key",
        "config/credentials.json",
    ],
)
def test_sensitive_paths_are_denied_inside_workspace(tmp_path: Path, relative_path: str) -> None:
    firewall, _ = make_firewall(tmp_path)

    result = authorize(firewall, relative_path)

    assert result.decision.decision is DecisionAction.DENY
    assert ReasonCode.SENSITIVE_PATH in result.decision.reason_codes


def test_ungranted_operation_is_denied(tmp_path: Path) -> None:
    firewall, _ = make_firewall(tmp_path)

    result = authorize(firewall, "file.txt", FilesystemOperation.DELETE)

    assert result.decision.decision is DecisionAction.DENY
    assert ReasonCode.FILESYSTEM_OPERATION_NOT_ALLOWED in result.decision.reason_codes


def test_no_grants_defaults_to_deny(tmp_path: Path) -> None:
    firewall = FilesystemFirewall()

    result = authorize(firewall, str(tmp_path / "file.txt"))

    assert result.decision.decision is DecisionAction.DENY
    assert ReasonCode.PATH_OUTSIDE_ALLOWED_ROOT in result.decision.reason_codes


def test_relative_path_without_grant_is_invalid() -> None:
    firewall = FilesystemFirewall()

    result = authorize(firewall, "file.txt")

    assert result.decision.decision is DecisionAction.DENY
    assert result.decision.reason_codes == (ReasonCode.INVALID_PATH,)


def test_symlink_escape_is_denied(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    outside = tmp_path / "outside"
    workspace.mkdir()
    outside.mkdir()
    link = workspace / "escape"
    try:
        os.symlink(outside, link, target_is_directory=True)
    except OSError as exc:
        pytest.skip(f"symlink unavailable: {exc}")
    firewall, _ = make_firewall(workspace)

    result = authorize(firewall, "escape/secret.txt")

    assert result.decision.decision is DecisionAction.DENY
    assert ReasonCode.PATH_OUTSIDE_ALLOWED_ROOT in result.decision.reason_codes


def test_raw_sensitive_path_is_not_written_to_audit(tmp_path: Path) -> None:
    firewall, sink = make_firewall(tmp_path)
    raw_path = str(tmp_path / ".ssh" / "id_rsa")

    authorize(firewall, raw_path)

    assert raw_path not in sink.records[0]


@pytest.mark.parametrize(
    "dangerous_path",
    [
        r"\\server\share\file.txt",
        r"\\?\C:\workspace\file.txt",
        "file.txt:alternate_stream",
        "NUL.txt",
    ],
)
def test_windows_special_paths_are_denied_before_resolution(
    tmp_path: Path,
    dangerous_path: str,
) -> None:
    firewall, _ = make_firewall(tmp_path)

    result = authorize(firewall, dangerous_path)

    assert result.decision.decision is DecisionAction.DENY
    assert result.decision.reason_codes == (ReasonCode.INVALID_PATH,)


def test_relative_path_is_denied_when_multiple_roots_are_ambiguous(tmp_path: Path) -> None:
    grants = tuple(
        FilesystemGrant(root=tmp_path / name, operations=frozenset({FilesystemOperation.READ}))
        for name in ("one", "two")
    )
    firewall = FilesystemFirewall(grants)

    result = authorize(firewall, "relative.txt")

    assert result.decision.decision is DecisionAction.DENY
    assert result.decision.reason_codes == (ReasonCode.INVALID_PATH,)
