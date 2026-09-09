from __future__ import annotations

from datetime import UTC, datetime
import json
import os
from pathlib import Path
import threading

from pydantic import BaseModel, ConfigDict, Field

from policy.signing import SignedPolicyBundle


class PolicyApproval(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    approval_id: str = Field(min_length=3, max_length=128, pattern=r"^[a-z0-9]+(?:[._-][a-z0-9]+)*$")
    approver_id: str = Field(min_length=3, max_length=128, pattern=r"^[a-z0-9]+(?:[._-][a-z0-9]+)*$")
    bundle_fingerprint: str = Field(pattern=r"^[a-f0-9]{64}$")
    approved_at: datetime


class DurablePolicyBundleStore:
    """Local append-only signed bundle store; deployment may replace it."""

    def __init__(self, path: str | Path, *, max_record_bytes: int = 4 * 1024 * 1024) -> None:
        candidate = Path(path)
        if not candidate.is_absolute():
            raise ValueError("policy store path must be absolute")
        resolved = candidate.resolve(strict=False)
        if resolved.exists() and resolved.is_symlink():
            raise ValueError("policy store path must not be a symlink")
        if not resolved.parent.is_dir():
            raise ValueError("policy store parent directory must already exist")
        if not 1024 <= max_record_bytes <= 64 * 1024 * 1024:
            raise ValueError("policy record bound is outside supported limits")
        self._path = resolved
        self._max_record_bytes = max_record_bytes
        self._lock = threading.RLock()

    def append(self, signed: SignedPolicyBundle, approval: PolicyApproval) -> None:
        if approval.bundle_fingerprint != signed.bundle.content_fingerprint:
            raise ValueError("approval does not match policy bundle")
        payload = {"signed": signed.model_dump(mode="json"), "approval": approval.model_dump(mode="json")}
        encoded = (json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
        if len(encoded) > self._max_record_bytes:
            raise ValueError("policy record exceeds configured bound")
        with self._lock:
            fd = os.open(self._path, os.O_APPEND | os.O_CREAT | os.O_WRONLY, 0o600)
            try:
                os.write(fd, encoded)
                os.fsync(fd)
            finally:
                os.close(fd)

    def load_latest(self) -> tuple[SignedPolicyBundle, PolicyApproval] | None:
        if not self._path.exists() or self._path.stat().st_size == 0:
            return None
        latest: tuple[SignedPolicyBundle, PolicyApproval] | None = None
        with self._lock, self._path.open("rb") as stream:
            for raw_line in stream:
                if len(raw_line) > self._max_record_bytes:
                    raise ValueError("policy record exceeds configured bound")
                payload = json.loads(raw_line)
                latest = (
                    SignedPolicyBundle.model_validate(payload["signed"]),
                    PolicyApproval.model_validate(payload["approval"]),
                )
        return latest


def create_approval(approval_id: str, approver_id: str, signed: SignedPolicyBundle) -> PolicyApproval:
    return PolicyApproval(
        approval_id=approval_id,
        approver_id=approver_id,
        bundle_fingerprint=signed.bundle.content_fingerprint,
        approved_at=datetime.now(UTC),
    )

