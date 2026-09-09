import json

import pytest

from telemetry.audit import AppendOnlyFileAuditSink, AuditIntegrityError


def test_append_only_sink_chains_and_verifies(tmp_path) -> None:
    sink = AppendOnlyFileAuditSink(tmp_path / "audit.jsonl")

    sink.write(json.dumps({"event_id": "one", "metadata": {"token": {"redacted": True}}}))
    sink.write(json.dumps({"event_id": "two", "metadata": {}}))

    assert sink.verify() == 2


def test_append_only_sink_rejects_relative_and_symlink_paths(tmp_path) -> None:
    with pytest.raises(ValueError):
        AppendOnlyFileAuditSink("relative-audit.jsonl")
    link = tmp_path / "audit-link.jsonl"
    target = tmp_path / "audit.jsonl"
    target.write_text("", encoding="utf-8")
    try:
        link.symlink_to(target)
    except OSError:
        pytest.skip("symlink privilege unavailable")
    with pytest.raises(ValueError):
        AppendOnlyFileAuditSink(link)


def test_append_only_sink_detects_tampering(tmp_path) -> None:
    path = tmp_path / "audit.jsonl"
    sink = AppendOnlyFileAuditSink(path)
    sink.write(json.dumps({"event_id": "one"}))
    path.write_text(path.read_text(encoding="utf-8").replace('"one"', '"tampered"'), encoding="utf-8")

    with pytest.raises(AuditIntegrityError):
        sink.verify()
