import hashlib
import json
import logging
import os
from pathlib import Path
import stat
import subprocess
import threading
from contextlib import contextmanager
from datetime import UTC, datetime
from typing import Any, Protocol

from pydantic import BaseModel, ConfigDict

from core.decisions.models import SecurityDecision
from core.events.models import SecurityEvent


SENSITIVE_KEY_MARKERS = ("secret", "token", "password", "credential", "api_key", "authorization")


def _fingerprint(value: Any) -> str:
    raw = str(value).encode("utf-8", errors="replace")
    return hashlib.sha256(raw).hexdigest()[:16]


def redact(value: Any, key: str = "") -> Any:
    lowered = key.lower()
    if any(marker in lowered for marker in SENSITIVE_KEY_MARKERS):
        return {"redacted": True, "fingerprint": _fingerprint(value)}
    if isinstance(value, dict):
        return {str(item_key): redact(item, str(item_key)) for item_key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [redact(item) for item in value]
    return value


class AuditRecord(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    audit_timestamp: datetime
    event_id: str
    event_type: str
    decision: str
    risk_score: int
    reason_codes: tuple[str, ...]
    matched_rules: tuple[str, ...]
    metadata: dict[str, Any]


class AuditSink(Protocol):
    def write(self, serialized_record: str) -> None: ...


class ImmutableAuditReplica(Protocol):
    def put_if_absent(self, record_id: str, serialized_record: str) -> bool: ...


class LoggingAuditSink:
    def __init__(self, logger: logging.Logger | None = None) -> None:
        self._logger = logger or logging.getLogger("ai_security.audit")

    def write(self, serialized_record: str) -> None:
        self._logger.info(serialized_record)


class InMemoryAuditSink:
    def __init__(self) -> None:
        self.records: list[str] = []

    def write(self, serialized_record: str) -> None:
        self.records.append(serialized_record)


class RequiredReplicatedAuditSink:
    """Require immutable replica acknowledgement before local commit."""

    def __init__(self, local: AuditSink, replicas: tuple[ImmutableAuditReplica, ...]) -> None:
        if not replicas:
            raise ValueError("at least one required audit replica is needed")
        self._local = local
        self._replicas = replicas

    def write(self, serialized_record: str) -> None:
        record_id = hashlib.sha256(serialized_record.encode("utf-8")).hexdigest()
        for replica in self._replicas:
            try:
                acknowledged = replica.put_if_absent(record_id, serialized_record)
            except Exception as exc:
                raise AuditDurabilityError("required audit replica unavailable") from exc
            if not acknowledged:
                raise AuditDurabilityError("required audit replica rejected record")
        self._local.write(serialized_record)


class DirectoryWormAuditReplica:
    """Put-once adapter for an immutable local or remotely mounted directory."""

    def __init__(self, directory: str | Path, *, fsync: bool = True) -> None:
        candidate = Path(directory)
        if not candidate.is_absolute() or not candidate.is_dir():
            raise ValueError("replica directory must be an existing absolute directory")
        self._directory = candidate.resolve(strict=True)
        self._fsync = fsync

    def put_if_absent(self, record_id: str, serialized_record: str) -> bool:
        if len(record_id) != 64 or any(char not in "0123456789abcdef" for char in record_id):
            raise ValueError("record id must be a SHA-256 hex digest")
        payload = serialized_record.encode("utf-8")
        target = self._directory / f"{record_id}.json"
        flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            fd = os.open(target, flags, 0o600)
        except FileExistsError:
            return target.read_bytes() == payload
        try:
            _harden_owner_only(target)
            view = memoryview(payload)
            while view:
                written = os.write(fd, view)
                if written <= 0:
                    raise AuditDurabilityError("replica write was incomplete")
                view = view[written:]
            if self._fsync:
                os.fsync(fd)
        finally:
            os.close(fd)
        return True


class AuditIntegrityError(ValueError):
    """Raised when an append-only audit chain is malformed or tampered with."""


class AuditDurabilityError(RuntimeError):
    """Raised when a required durable audit destination does not acknowledge."""


@contextmanager
def _exclusive_file_lock(path: Path):
    """Serialize writers across threads and processes using a sidecar lock."""
    fd = os.open(path, os.O_CREAT | os.O_RDWR, 0o600)
    try:
        if os.name == "nt":
            import msvcrt

            if os.fstat(fd).st_size == 0:
                os.write(fd, b"\0")
            os.lseek(fd, 0, os.SEEK_SET)
            msvcrt.locking(fd, msvcrt.LK_LOCK, 1)
        else:
            import fcntl

            fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        if os.name == "nt":
            os.lseek(fd, 0, os.SEEK_SET)
            msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
        else:
            fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


def _harden_owner_only(path: Path) -> None:
    if os.name == "nt":
        identity = subprocess.run(
            ["whoami"], shell=False, check=True, capture_output=True, text=True
        ).stdout.strip()
        result = subprocess.run(
            ["icacls", str(path), "/inheritance:r", "/grant:r", f"{identity}:(F)"],
            shell=False,
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            raise AuditDurabilityError("failed to apply owner-only audit DACL")
    else:
        path.chmod(stat.S_IRUSR | stat.S_IWUSR)


class AppendOnlyFileAuditSink:
    """Write redacted audit records to a bounded, hash-chained JSONL file."""

    def __init__(
        self,
        path: str | Path,
        *,
        fsync: bool = True,
        max_record_bytes: int = 1_048_576,
    ) -> None:
        candidate = Path(path)
        if not candidate.is_absolute():
            raise ValueError("audit path must be absolute")
        if candidate.is_symlink():
            raise ValueError("audit path must not be a symlink")
        resolved = candidate.resolve(strict=False)
        if not resolved.parent.is_dir():
            raise ValueError("audit parent directory must already exist")
        if max_record_bytes < 1024 or max_record_bytes > 16 * 1024 * 1024:
            raise ValueError("audit record bound is outside supported limits")
        self._path = resolved
        self._lock_path = resolved.with_name(f".{resolved.name}.lock")
        self._fsync = fsync
        self._max_record_bytes = max_record_bytes
        self._lock = threading.RLock()
        if self._path.exists():
            self._validate_target()
            _harden_owner_only(self._path)
            with _exclusive_file_lock(self._lock_path):
                self._verify_unlocked()

    @property
    def path(self) -> Path:
        return self._path

    def write(self, serialized_record: str) -> None:
        if not isinstance(serialized_record, str) or not serialized_record:
            raise ValueError("serialized audit record must be non-empty text")
        try:
            record = json.loads(serialized_record)
        except json.JSONDecodeError as exc:
            raise ValueError("serialized audit record must be JSON") from exc
        if not isinstance(record, dict):
            raise ValueError("serialized audit record must be an object")
        with self._lock:
            with _exclusive_file_lock(self._lock_path):
                self._validate_target()
                _, previous_hash = self._verify_unlocked()
                envelope = {"record": record, "previous_hash": previous_hash}
                canonical = json.dumps(envelope, sort_keys=True, separators=(",", ":"))
                envelope["record_hash"] = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
                encoded = (
                    json.dumps(envelope, sort_keys=True, separators=(",", ":")) + "\n"
                ).encode("utf-8")
                if len(encoded) > self._max_record_bytes:
                    raise ValueError("audit record exceeds configured bound")
                flags = os.O_APPEND | os.O_CREAT | os.O_WRONLY
                if hasattr(os, "O_NOFOLLOW"):
                    flags |= os.O_NOFOLLOW
                fd = os.open(self._path, flags, 0o600)
                try:
                    if os.fstat(fd).st_size == 0:
                        _harden_owner_only(self._path)
                    view = memoryview(encoded)
                    while view:
                        written = os.write(fd, view)
                        if written <= 0:
                            raise AuditDurabilityError("audit append was incomplete")
                        view = view[written:]
                    if self._fsync:
                        os.fsync(fd)
                finally:
                    os.close(fd)

    def verify(self) -> int:
        """Verify the complete chain and return the number of records."""
        with self._lock, _exclusive_file_lock(self._lock_path):
            self._validate_target()
            count, _ = self._verify_unlocked()
            return count

    def tail_hash(self) -> str:
        """Verify the chain and return its trusted tail hash."""
        with self._lock, _exclusive_file_lock(self._lock_path):
            self._validate_target()
            _, tail = self._verify_unlocked()
            return tail

    def _verify_unlocked(self) -> tuple[int, str]:
        previous = ""
        count = 0
        if not self._path.exists():
            return 0, previous
        with self._path.open("rb") as stream:
            for raw_line in stream:
                if len(raw_line) > self._max_record_bytes:
                    raise AuditIntegrityError("audit record exceeds configured bound")
                try:
                    envelope = json.loads(raw_line)
                    record_hash = envelope.pop("record_hash")
                    expected = hashlib.sha256(
                        json.dumps(envelope, sort_keys=True, separators=(",", ":")).encode("utf-8")
                    ).hexdigest()
                except (json.JSONDecodeError, KeyError, TypeError) as exc:
                    raise AuditIntegrityError("invalid audit envelope") from exc
                if envelope.get("previous_hash") != previous or record_hash != expected:
                    raise AuditIntegrityError("audit hash chain mismatch")
                previous = record_hash
                count += 1
        return count, previous

    def _validate_target(self) -> None:
        if self._path.is_symlink() or self._path.resolve(strict=False) != self._path:
            raise AuditIntegrityError("audit path identity changed")


class SegmentedAuditFileSink:
    """Rotate hash-linked local segments and retain a verified recovery anchor."""

    def __init__(
        self,
        directory: str | Path,
        *,
        max_segment_bytes: int = 64 * 1024 * 1024,
        retention_segments: int = 30,
        fsync: bool = True,
    ) -> None:
        candidate = Path(directory)
        if not candidate.is_absolute() or not candidate.is_dir():
            raise ValueError("audit directory must be an existing absolute directory")
        if not 4096 <= max_segment_bytes <= 4 * 1024**3:
            raise ValueError("segment bound is outside supported limits")
        if not 2 <= retention_segments <= 10_000:
            raise ValueError("retention segment count is outside supported limits")
        self._directory = candidate.resolve(strict=True)
        self._max_segment_bytes = max_segment_bytes
        self._retention_segments = retention_segments
        self._fsync = fsync
        self._lock_path = self._directory / ".audit-segments.lock"
        self._manifest_path = self._directory / "audit-retention.json"
        self._lock = threading.RLock()

    def write(self, serialized_record: str) -> None:
        with self._lock, _exclusive_file_lock(self._lock_path):
            segments = self._segments()
            if segments:
                sequence, path = segments[-1]
                sink = AppendOnlyFileAuditSink(path, fsync=self._fsync)
            else:
                sequence = 1
                sink = self._new_segment(sequence, self._manifest_anchor())
            estimated_bytes = len(serialized_record.encode("utf-8")) + 512
            if (
                sink.path.exists()
                and sink.path.stat().st_size + estimated_bytes > self._max_segment_bytes
                and sink.verify() > 1
            ):
                previous = sink.tail_hash()
                sequence += 1
                sink = self._new_segment(sequence, previous)
            sink.write(serialized_record)
            self._enforce_retention()

    def verify(self) -> int:
        with self._lock, _exclusive_file_lock(self._lock_path):
            previous = self._manifest_anchor()
            total = 0
            for sequence, path in self._segments():
                sink = AppendOnlyFileAuditSink(path, fsync=self._fsync)
                count = sink.verify()
                header = self._segment_header(path)
                if (
                    header.get("sequence") != sequence
                    or header.get("previous_segment_hash") != previous
                ):
                    raise AuditIntegrityError("audit segment linkage mismatch")
                previous = sink.tail_hash()
                total += max(0, count - 1)
            return total

    def _new_segment(self, sequence: int, previous: str) -> AppendOnlyFileAuditSink:
        path = self._directory / f"audit-{sequence:08d}.jsonl"
        if path.exists():
            raise AuditIntegrityError("audit segment sequence already exists")
        sink = AppendOnlyFileAuditSink(path, fsync=self._fsync)
        sink.write(json.dumps({
            "audit_segment": {
                "sequence": sequence,
                "previous_segment_hash": previous,
            }
        }, sort_keys=True, separators=(",", ":")))
        return sink

    def _segments(self) -> list[tuple[int, Path]]:
        segments: list[tuple[int, Path]] = []
        for path in self._directory.glob("audit-????????.jsonl"):
            try:
                sequence = int(path.stem.removeprefix("audit-"))
            except ValueError as exc:
                raise AuditIntegrityError("invalid audit segment name") from exc
            segments.append((sequence, path))
        segments.sort()
        if segments and [item[0] for item in segments] != list(
            range(segments[0][0], segments[-1][0] + 1)
        ):
            raise AuditIntegrityError("audit segment sequence gap")
        return segments

    @staticmethod
    def _segment_header(path: Path) -> dict[str, Any]:
        try:
            first = json.loads(path.read_text(encoding="utf-8").splitlines()[0])
            header = first["record"]["audit_segment"]
        except (IndexError, KeyError, TypeError, json.JSONDecodeError) as exc:
            raise AuditIntegrityError("invalid audit segment header") from exc
        if not isinstance(header, dict):
            raise AuditIntegrityError("invalid audit segment header")
        return header

    def _enforce_retention(self) -> None:
        segments = self._segments()
        while len(segments) > self._retention_segments:
            _, expired = segments.pop(0)
            anchor = AppendOnlyFileAuditSink(expired, fsync=self._fsync).tail_hash()
            self._write_manifest(segments[0][0], anchor)
            expired.unlink()

    def _write_manifest(self, first_sequence: int, previous_hash: str) -> None:
        body = {"first_sequence": first_sequence, "previous_segment_hash": previous_hash}
        manifest = {
            **body,
            "manifest_hash": hashlib.sha256(
                json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")
            ).hexdigest(),
        }
        temporary = self._directory / f".audit-retention.{os.getpid()}.{threading.get_ident()}.tmp"
        data = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode("utf-8")
        fd = os.open(temporary, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        try:
            _harden_owner_only(temporary)
            view = memoryview(data)
            while view:
                written = os.write(fd, view)
                if written <= 0:
                    raise AuditDurabilityError("retention manifest write was incomplete")
                view = view[written:]
            if self._fsync:
                os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(temporary, self._manifest_path)
        _harden_owner_only(self._manifest_path)

    def _manifest_anchor(self) -> str:
        if not self._manifest_path.exists():
            return ""
        try:
            manifest = json.loads(self._manifest_path.read_text(encoding="utf-8"))
            manifest_hash = manifest.pop("manifest_hash")
            expected = hashlib.sha256(
                json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode("utf-8")
            ).hexdigest()
            anchor = manifest["previous_segment_hash"]
        except (json.JSONDecodeError, KeyError, TypeError) as exc:
            raise AuditIntegrityError("invalid retention manifest") from exc
        if manifest_hash != expected or not isinstance(anchor, str):
            raise AuditIntegrityError("retention manifest integrity mismatch")
        return anchor


class StructuredAuditLogger:
    def __init__(self, sink: AuditSink | None = None) -> None:
        self._sink = sink or LoggingAuditSink()

    def record(self, event: SecurityEvent, decision: SecurityDecision) -> AuditRecord:
        record = AuditRecord(
            audit_timestamp=datetime.now(UTC),
            event_id=event.event_id,
            event_type=event.event_type,
            decision=decision.decision.value,
            risk_score=decision.risk_score,
            reason_codes=tuple(code.value for code in decision.reason_codes),
            matched_rules=decision.matched_rules,
            metadata=redact({"event_data": event.data, "decision": decision.metadata}),
        )
        self._sink.write(json.dumps(record.model_dump(mode="json"), sort_keys=True, separators=(",", ":")))
        return record
