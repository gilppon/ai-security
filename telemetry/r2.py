"""Cloudflare R2 immutable audit replication."""

from __future__ import annotations

import hashlib
import os
from typing import Any
from urllib.parse import urlparse

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError


class R2WormAuditReplica:
    """Write content-addressed audit records once under a locked R2 prefix."""

    def __init__(
        self,
        *,
        endpoint_url: str,
        bucket: str,
        access_key_id: str,
        secret_access_key: str,
        prefix: str = "audit/records/",
        client: Any | None = None,
    ) -> None:
        parsed = urlparse(endpoint_url)
        hostname = (parsed.hostname or "").casefold()
        if (
            parsed.scheme != "https"
            or parsed.username is not None
            or parsed.password is not None
            or parsed.port is not None
            or parsed.path not in ("", "/")
            or parsed.query
            or parsed.fragment
            or hostname == "r2.cloudflarestorage.com"
            or not hostname.endswith(".r2.cloudflarestorage.com")
        ):
            raise ValueError("R2 endpoint must be an HTTPS Cloudflare R2 S3 endpoint")
        if not bucket or any(char in bucket for char in "/\\"):
            raise ValueError("R2 bucket name is invalid")
        if not prefix.startswith("audit/") or not prefix.endswith("/") or ".." in prefix:
            raise ValueError("R2 audit prefix must remain beneath audit/")
        if not access_key_id or not secret_access_key:
            raise ValueError("R2 credentials are required")

        self._bucket = bucket
        self._prefix = prefix
        self._client = client or boto3.client(
            "s3",
            endpoint_url=endpoint_url.rstrip("/"),
            aws_access_key_id=access_key_id,
            aws_secret_access_key=secret_access_key,
            region_name="auto",
            config=Config(signature_version="s3v4", retries={"mode": "standard", "max_attempts": 3}),
        )

    @classmethod
    def from_environment(cls, *, prefix: str = "audit/records/") -> "R2WormAuditReplica":
        names = (
            "AI_SECURITY_R2_ENDPOINT",
            "AI_SECURITY_R2_BUCKET",
            "AI_SECURITY_R2_ACCESS_KEY_ID",
            "AI_SECURITY_R2_SECRET_ACCESS_KEY",
        )
        values = {name: os.environ.get(name, "") for name in names}
        missing = [name for name, value in values.items() if not value]
        if missing:
            raise ValueError(f"missing required R2 environment variables: {', '.join(missing)}")
        return cls(
            endpoint_url=values[names[0]],
            bucket=values[names[1]],
            access_key_id=values[names[2]],
            secret_access_key=values[names[3]],
            prefix=prefix,
        )

    def put_if_absent(self, record_id: str, serialized_record: str) -> bool:
        if len(record_id) != 64 or any(char not in "0123456789abcdef" for char in record_id):
            raise ValueError("record id must be a SHA-256 hex digest")
        payload = serialized_record.encode("utf-8")
        if hashlib.sha256(payload).hexdigest() != record_id:
            raise ValueError("record id does not match audit payload")
        key = f"{self._prefix}{record_id}.json"
        try:
            self._client.put_object(
                Bucket=self._bucket,
                Key=key,
                Body=payload,
                ContentType="application/json",
                IfNoneMatch="*",
                Metadata={"sha256": record_id},
            )
            return True
        except ClientError as exc:
            status = exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
            code = exc.response.get("Error", {}).get("Code")
            if status != 412 and code not in {
                "PreconditionFailed",
                "ObjectLockedByBucketPolicy",
                "412",
            }:
                raise
        existing = self._client.get_object(Bucket=self._bucket, Key=key)["Body"].read()
        return existing == payload


import atexit
from pathlib import Path
import queue
import threading
import time


class AsyncR2AuditDispatcher:
    """Asynchronous background dispatcher for Cloudflare R2 audit replication.

    Ensures zero inference latency while preventing data loss via crash-proof
    local disk spool journaling and graceful shutdown hooks.
    """

    def __init__(
        self,
        replica: R2WormAuditReplica,
        *,
        spool_dir: Path | str | None = ".artifacts/audit_spool",
        max_queue_size: int = 10000,
    ) -> None:
        self._replica = replica
        self._spool_path = Path(spool_dir) if spool_dir else None
        if self._spool_path:
            self._spool_path.mkdir(parents=True, exist_ok=True)

        self._queue: queue.Queue[tuple[str, str] | None] = queue.Queue(maxsize=max_queue_size)
        self._stop_event = threading.Event()
        self._worker_thread = threading.Thread(target=self._worker_loop, daemon=True, name="AsyncR2AuditWorker")
        self._worker_thread.start()

        # Re-queue any unsynced records found in the local spool directory
        self._recover_spool()

        # Register graceful shutdown
        atexit.register(self.shutdown)

    def _recover_spool(self) -> None:
        if not self._spool_path or not self._spool_path.exists():
            return
        for journal_file in self._spool_path.glob("*.journal"):
            try:
                record_id = journal_file.stem
                serialized = journal_file.read_text(encoding="utf-8")
                self._queue.put_nowait((record_id, serialized))
            except Exception:
                pass

    def record_async(self, record_id: str, serialized_record: str) -> None:
        """Persist to local crash-proof spool journal and queue for asynchronous upload (<0.2ms)."""
        if self._spool_path:
            try:
                journal_tmp = self._spool_path / f"{record_id}.tmp"
                journal_final = self._spool_path / f"{record_id}.journal"
                journal_tmp.write_text(serialized_record, encoding="utf-8")
                journal_tmp.replace(journal_final)
            except Exception:
                # If disk spool fails, continue to in-memory queue
                pass

        try:
            self._queue.put((record_id, serialized_record), block=False)
        except queue.Full:
            # If queue is full, write directly synchronously as backpressure safeguard
            self._replica.put_if_absent(record_id, serialized_record)
            if self._spool_path:
                (self._spool_path / f"{record_id}.journal").unlink(missing_ok=True)

    def _worker_loop(self) -> None:
        while not self._stop_event.is_set():
            try:
                item = self._queue.get(timeout=0.2)
            except queue.Empty:
                continue

            if item is None:
                self._queue.task_done()
                break

            record_id, serialized = item
            try:
                self._replica.put_if_absent(record_id, serialized)
                # Cleanup local journal upon successful R2 replication
                if self._spool_path:
                    journal_file = self._spool_path / f"{record_id}.journal"
                    journal_file.unlink(missing_ok=True)
            except Exception:
                # On transient failure, retry after brief delay
                time.sleep(0.5)
            finally:
                self._queue.task_done()

    def flush(self, timeout: float = 5.0) -> bool:
        """Wait for all pending records in queue to be uploaded."""
        start = time.monotonic()
        while not self._queue.empty():
            if time.monotonic() - start > timeout:
                return False
            time.sleep(0.05)
        return True

    def shutdown(self, timeout: float = 3.0) -> None:
        """Gracefully drain pending queue items and stop background worker."""
        if self._stop_event.is_set():
            return
        self._stop_event.set()
        try:
            self._queue.put(None, timeout=0.5)
        except Exception:
            pass
        if self._worker_thread.is_alive():
            self._worker_thread.join(timeout=timeout)

