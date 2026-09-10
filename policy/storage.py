from __future__ import annotations

from contextlib import contextmanager
from datetime import UTC, datetime
import hashlib
import hmac
import json
import os
from pathlib import Path
import threading

from pydantic import BaseModel, ConfigDict, Field, field_validator

from policy.signing import SignedPolicyBundle


class PolicyStoreError(ValueError):
    """Raised when the durable policy history is malformed."""


class PolicyVersionRollbackError(PolicyStoreError):
    """Raised when policy history is not strictly monotonic."""


class PolicyApproval(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    approval_id: str = Field(min_length=3, max_length=128, pattern=r"^[a-z0-9]+(?:[._-][a-z0-9]+)*$")
    approver_id: str = Field(min_length=3, max_length=128, pattern=r"^[a-z0-9]+(?:[._-][a-z0-9]+)*$")
    policy_id: str = Field(min_length=3, max_length=128, pattern=r"^[a-z0-9]+(?:[._-][a-z0-9]+)*$")
    policy_version: int = Field(ge=1)
    bundle_fingerprint: str = Field(pattern=r"^[a-f0-9]{64}$")
    signer_id: str = Field(min_length=3, max_length=128, pattern=r"^[a-z0-9]+(?:[._-][a-z0-9]+)*$")
    approved_at: datetime
    signature: str = Field(pattern=r"^[a-f0-9]{64}$")

    @field_validator("approved_at")
    @classmethod
    def require_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("approval timestamp must be timezone-aware")
        return value.astimezone(UTC)


def _approval_payload(approval: PolicyApproval) -> bytes:
    return json.dumps(
        approval.model_dump(mode="json", exclude={"signature"}),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


class PolicyApprovalVerifier:
    def __init__(
        self,
        keys: dict[str, bytes],
        *,
        revoked_approver_ids: set[str] | frozenset[str] = frozenset(),
    ) -> None:
        if not keys or any(
            not approver_id or not isinstance(key, bytes) or len(key) < 32
            for approver_id, key in keys.items()
        ):
            raise ValueError("policy approval verifier requires non-empty 32-byte keys")
        self._keys = dict(keys)
        self._revoked_approver_ids = frozenset(revoked_approver_ids)
        self._lock = threading.RLock()

    def verify(self, approval: PolicyApproval) -> bool:
        with self._lock:
            key = self._keys.get(approval.approver_id)
            revoked = approval.approver_id in self._revoked_approver_ids
        if key is None or revoked:
            return False
        expected = hmac.new(key, _approval_payload(approval), hashlib.sha256).hexdigest()
        return hmac.compare_digest(expected, approval.signature)


def approval_matches_bundle(approval: PolicyApproval, signed: SignedPolicyBundle) -> bool:
    bundle = signed.bundle
    return (
        approval.policy_id == bundle.policy_id
        and approval.policy_version == bundle.version
        and hmac.compare_digest(approval.bundle_fingerprint, bundle.content_fingerprint)
        and approval.signer_id == signed.signer_id
    )


class DurablePolicyBundleStore:
    """Cross-process serialized, monotonic signed policy history."""

    def __init__(self, path: str | Path, *, max_record_bytes: int = 4 * 1024 * 1024) -> None:
        candidate = Path(path)
        if not candidate.is_absolute():
            raise ValueError("policy store path must be absolute")
        if candidate.is_symlink():
            raise ValueError("policy store path must not be a symlink")
        resolved = candidate.resolve(strict=False)
        if not resolved.parent.is_dir():
            raise ValueError("policy store parent directory must already exist")
        if not 1024 <= max_record_bytes <= 64 * 1024 * 1024:
            raise ValueError("policy record bound is outside supported limits")
        self._path = resolved
        self._lock_path = resolved.with_name(f".{resolved.name}.lock")
        self._max_record_bytes = max_record_bytes
        self._lock = threading.RLock()
        if self._path.exists():
            self._validate_target()
            self._path.chmod(0o600)

    def append(self, signed: SignedPolicyBundle, approval: PolicyApproval) -> None:
        if not signed.bundle.has_valid_fingerprint():
            raise PolicyStoreError("policy content fingerprint mismatch")
        if not approval_matches_bundle(approval, signed):
            raise ValueError("approval does not match policy bundle")
        payload = {"signed": signed.model_dump(mode="json"), "approval": approval.model_dump(mode="json")}
        encoded = (json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
        if len(encoded) > self._max_record_bytes:
            raise ValueError("policy record exceeds configured bound")
        with self._lock, _exclusive_file_lock(self._lock_path):
            records = self._read_records_unlocked()
            if records:
                previous = records[-1][0].bundle
                if signed.bundle.policy_id != previous.policy_id:
                    raise PolicyStoreError("policy id switch is not allowed")
                if signed.bundle.version <= previous.version:
                    raise PolicyVersionRollbackError("policy version must increase monotonically")
            self._validate_target(allow_missing=True)
            flags = os.O_APPEND | os.O_CREAT | os.O_WRONLY
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            fd = os.open(self._path, flags, 0o600)
            try:
                view = memoryview(encoded)
                while view:
                    written = os.write(fd, view)
                    if written <= 0:
                        raise PolicyStoreError("policy record write was incomplete")
                    view = view[written:]
                os.fsync(fd)
            finally:
                os.close(fd)
            self._path.chmod(0o600)

    def load_latest(self) -> tuple[SignedPolicyBundle, PolicyApproval] | None:
        with self._lock, _exclusive_file_lock(self._lock_path):
            records = self._read_records_unlocked()
        return records[-1] if records else None

    def _read_records_unlocked(self) -> list[tuple[SignedPolicyBundle, PolicyApproval]]:
        if not self._path.exists() or self._path.stat().st_size == 0:
            return []
        self._validate_target()
        records: list[tuple[SignedPolicyBundle, PolicyApproval]] = []
        with self._path.open("rb") as stream:
            for raw_line in stream:
                if len(raw_line) > self._max_record_bytes:
                    raise PolicyStoreError("policy record exceeds configured bound")
                try:
                    payload = json.loads(raw_line)
                    signed = SignedPolicyBundle.model_validate(payload["signed"])
                    approval = PolicyApproval.model_validate(payload["approval"])
                except (json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
                    raise PolicyStoreError("invalid policy store record") from exc
                if not approval_matches_bundle(approval, signed):
                    raise PolicyStoreError("approval does not match policy bundle")
                if records:
                    previous = records[-1][0].bundle
                    if signed.bundle.policy_id != previous.policy_id:
                        raise PolicyStoreError("policy id switch is not allowed")
                    if signed.bundle.version <= previous.version:
                        raise PolicyVersionRollbackError("policy history contains a rollback")
                records.append((signed, approval))
        return records

    def _validate_target(self, *, allow_missing: bool = False) -> None:
        if self._path.is_symlink():
            raise ValueError("policy store path must not be a symlink")
        if not self._path.exists():
            if allow_missing:
                return
            raise PolicyStoreError("policy store is missing")
        if not self._path.is_file():
            raise PolicyStoreError("policy store path must be a regular file")


def create_approval(
    approval_id: str,
    approver_id: str,
    signed: SignedPolicyBundle,
    *,
    key: bytes,
) -> PolicyApproval:
    if not isinstance(key, bytes) or len(key) < 32:
        raise ValueError("policy approval key must contain at least 32 bytes")
    unsigned = PolicyApproval(
        approval_id=approval_id,
        approver_id=approver_id,
        policy_id=signed.bundle.policy_id,
        policy_version=signed.bundle.version,
        bundle_fingerprint=signed.bundle.content_fingerprint,
        signer_id=signed.signer_id,
        approved_at=datetime.now(UTC),
        signature="0" * 64,
    )
    signature = hmac.new(key, _approval_payload(unsigned), hashlib.sha256).hexdigest()
    return unsigned.model_copy(update={"signature": signature})


@contextmanager
def _exclusive_file_lock(path: Path):
    flags = os.O_CREAT | os.O_RDWR
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(path, flags, 0o600)
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
