import hashlib
import json
import logging
import os
from pathlib import Path
import threading
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


class AuditIntegrityError(ValueError):
    """Raised when an append-only audit chain is malformed or tampered with."""


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
        resolved = candidate.resolve(strict=False)
        if resolved.exists() and resolved.is_symlink():
            raise ValueError("audit path must not be a symlink")
        if not resolved.parent.is_dir():
            raise ValueError("audit parent directory must already exist")
        if max_record_bytes < 1024 or max_record_bytes > 16 * 1024 * 1024:
            raise ValueError("audit record bound is outside supported limits")
        self._path = resolved
        self._fsync = fsync
        self._max_record_bytes = max_record_bytes
        self._previous_hash = self._read_tail_hash()
        self._lock = threading.RLock()

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
            envelope = {
                "record": record,
                "previous_hash": self._previous_hash,
            }
            canonical = json.dumps(envelope, sort_keys=True, separators=(",", ":"))
            record_hash = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
            envelope["record_hash"] = record_hash
            line = json.dumps(envelope, sort_keys=True, separators=(",", ":")) + "\n"
            encoded = line.encode("utf-8")
            if len(encoded) > self._max_record_bytes:
                raise ValueError("audit record exceeds configured bound")
            flags = os.O_APPEND | os.O_CREAT | os.O_WRONLY
            fd = os.open(self._path, flags, 0o600)
            try:
                os.write(fd, encoded)
                if self._fsync:
                    os.fsync(fd)
            finally:
                os.close(fd)
            self._previous_hash = record_hash

    def verify(self) -> int:
        """Verify the complete chain and return the number of records."""
        previous = ""
        count = 0
        if not self._path.exists():
            return 0
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
        return count

    def _read_tail_hash(self) -> str:
        if not self._path.exists() or self._path.stat().st_size == 0:
            return ""
        last_line = ""
        with self._path.open("rb") as stream:
            for line in stream:
                last_line = line
        try:
            envelope = json.loads(last_line)
            record_hash = envelope["record_hash"]
        except (json.JSONDecodeError, KeyError, TypeError) as exc:
            raise AuditIntegrityError("existing audit tail is invalid") from exc
        if not isinstance(record_hash, str) or len(record_hash) != 64:
            raise AuditIntegrityError("existing audit tail hash is invalid")
        return record_hash


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
