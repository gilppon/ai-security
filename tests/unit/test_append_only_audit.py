import json
import multiprocessing
import os
import subprocess

import pytest

from telemetry.audit import (
    AppendOnlyFileAuditSink,
    AuditDurabilityError,
    AuditIntegrityError,
    DirectoryWormAuditReplica,
    InMemoryAuditSink,
    RequiredReplicatedAuditSink,
    SegmentedAuditFileSink,
)


def _write_audit_records(path: str, worker: int, count: int) -> None:
    sink = AppendOnlyFileAuditSink(path)
    for index in range(count):
        sink.write(json.dumps({"worker": worker, "index": index}))


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


def test_append_only_sink_checks_symlink_before_resolution(tmp_path, monkeypatch) -> None:
    candidate = tmp_path / "audit-link.jsonl"
    original_is_symlink = type(candidate).is_symlink

    monkeypatch.setattr(
        type(candidate),
        "is_symlink",
        lambda path: path == candidate or original_is_symlink(path),
    )

    with pytest.raises(ValueError, match="must not be a symlink"):
        AppendOnlyFileAuditSink(candidate)


def test_append_only_sink_detects_tampering(tmp_path) -> None:
    path = tmp_path / "audit.jsonl"
    sink = AppendOnlyFileAuditSink(path)
    sink.write(json.dumps({"event_id": "one"}))
    path.write_text(path.read_text(encoding="utf-8").replace('"one"', '"tampered"'), encoding="utf-8")

    with pytest.raises(AuditIntegrityError):
        sink.verify()

    with pytest.raises(AuditIntegrityError):
        sink.write(json.dumps({"event_id": "must-not-extend-tampering"}))


def test_independent_sinks_refresh_tail_under_cross_process_lock(tmp_path) -> None:
    path = tmp_path / "audit.jsonl"
    first = AppendOnlyFileAuditSink(path)
    second = AppendOnlyFileAuditSink(path)

    first.write(json.dumps({"event_id": "one"}))
    second.write(json.dumps({"event_id": "two"}))

    assert first.verify() == 2


def test_multiple_processes_preserve_one_hash_chain(tmp_path) -> None:
    path = tmp_path / "audit.jsonl"
    context = multiprocessing.get_context("spawn")
    workers = [
        context.Process(target=_write_audit_records, args=(str(path), worker, 10))
        for worker in range(3)
    ]
    for worker in workers:
        worker.start()
    for worker in workers:
        worker.join(timeout=15)

    assert [worker.exitcode for worker in workers] == [0, 0, 0]
    assert AppendOnlyFileAuditSink(path).verify() == 30


@pytest.mark.skipif(os.name != "nt", reason="Windows DACL verification")
def test_windows_audit_file_removes_inherited_acl(tmp_path) -> None:
    path = tmp_path / "audit.jsonl"
    sink = AppendOnlyFileAuditSink(path)
    sink.write(json.dumps({"event_id": "acl"}))

    acl = subprocess.run(
        ["icacls", str(path)], shell=False, check=True, capture_output=True, text=True
    ).stdout

    assert "(I)" not in acl
    assert subprocess.run(
        ["whoami"], shell=False, check=True, capture_output=True, text=True
    ).stdout.strip().casefold() in acl.casefold()


def test_required_replica_failure_prevents_local_success() -> None:
    class FailingReplica:
        def put_if_absent(self, record_id: str, serialized_record: str) -> bool:
            raise OSError("remote unavailable")

    local = InMemoryAuditSink()
    sink = RequiredReplicatedAuditSink(local, (FailingReplica(),))

    with pytest.raises(AuditDurabilityError):
        sink.write(json.dumps({"event_id": "denied"}))
    assert local.records == []


def test_directory_worm_replica_is_idempotent_and_rejects_replacement(tmp_path) -> None:
    replica = DirectoryWormAuditReplica(tmp_path)
    payload = json.dumps({"event_id": "one"})
    record_id = __import__("hashlib").sha256(payload.encode()).hexdigest()

    assert replica.put_if_absent(record_id, payload) is True
    assert replica.put_if_absent(record_id, payload) is True
    assert replica.put_if_absent(record_id, "different") is False


def test_segment_rotation_retention_and_recovery_verification(tmp_path) -> None:
    sink = SegmentedAuditFileSink(
        tmp_path,
        max_segment_bytes=4096,
        retention_segments=2,
    )

    for index in range(20):
        sink.write(json.dumps({"index": index, "padding": "x" * 800}))

    segments = sorted(tmp_path.glob("audit-????????.jsonl"))
    assert len(segments) == 2
    assert sink.verify() > 0
    assert (tmp_path / "audit-retention.json").is_file()


def test_segment_recovery_rejects_manifest_tampering(tmp_path) -> None:
    sink = SegmentedAuditFileSink(
        tmp_path,
        max_segment_bytes=4096,
        retention_segments=2,
    )
    for index in range(12):
        sink.write(json.dumps({"index": index, "padding": "x" * 800}))
    manifest = tmp_path / "audit-retention.json"
    manifest.write_text(
        manifest.read_text(encoding="utf-8").replace(
            '"previous_segment_hash":"', '"previous_segment_hash":"tampered'
        ),
        encoding="utf-8",
    )

    with pytest.raises(AuditIntegrityError):
        sink.verify()
