from __future__ import annotations

import hashlib
import hmac
import threading

from pydantic import BaseModel, ConfigDict, Field

from policy.lifecycle import PolicyBundle, canonical_policy_bundle_bytes


class SignedPolicyBundle(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    bundle: PolicyBundle
    signer_id: str = Field(min_length=3, max_length=128, pattern=r"^[a-z0-9]+(?:[._-][a-z0-9]+)*$")
    signature: str = Field(pattern=r"^[a-f0-9]{64}$")


def _signing_payload(bundle: PolicyBundle) -> bytes:
    return canonical_policy_bundle_bytes(bundle)


def sign_policy_bundle(bundle: PolicyBundle, *, signer_id: str, key: bytes) -> SignedPolicyBundle:
    if not isinstance(key, bytes) or len(key) < 32:
        raise ValueError("policy signing key must contain at least 32 bytes")
    if not bundle.has_valid_fingerprint():
        raise ValueError("policy content fingerprint mismatch")
    signature = hmac.new(key, _signing_payload(bundle), hashlib.sha256).hexdigest()
    return SignedPolicyBundle(bundle=bundle, signer_id=signer_id, signature=signature)


class PolicySignatureVerifier:
    def __init__(
        self,
        keys: dict[str, bytes],
        *,
        revoked_signer_ids: set[str] | frozenset[str] = frozenset(),
    ) -> None:
        if not keys or any(not signer_id or not isinstance(key, bytes) or len(key) < 32 for signer_id, key in keys.items()):
            raise ValueError("policy verifier requires non-empty 32-byte keys")
        self._keys = dict(keys)
        self._revoked_signer_ids = frozenset(revoked_signer_ids)
        self._lock = threading.RLock()

    def verify(self, signed: SignedPolicyBundle) -> bool:
        with self._lock:
            key = self._keys.get(signed.signer_id)
            revoked = signed.signer_id in self._revoked_signer_ids
        if key is None or revoked or not signed.bundle.has_valid_fingerprint():
            return False
        expected = hmac.new(key, _signing_payload(signed.bundle), hashlib.sha256).hexdigest()
        return hmac.compare_digest(expected, signed.signature)
