from __future__ import annotations

import hashlib
import hmac
import threading

from pydantic import BaseModel, ConfigDict, Field

from policy.lifecycle import PolicyBundle


class SignedPolicyBundle(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    bundle: PolicyBundle
    signer_id: str = Field(min_length=3, max_length=128, pattern=r"^[a-z0-9]+(?:[._-][a-z0-9]+)*$")
    signature: str = Field(pattern=r"^[a-f0-9]{64}$")


def _signing_payload(bundle: PolicyBundle) -> bytes:
    return f"{bundle.policy_id}\n{bundle.version}\n{bundle.content_fingerprint}".encode("utf-8")


def sign_policy_bundle(bundle: PolicyBundle, *, signer_id: str, key: bytes) -> SignedPolicyBundle:
    if not isinstance(key, bytes) or len(key) < 32:
        raise ValueError("policy signing key must contain at least 32 bytes")
    signature = hmac.new(key, _signing_payload(bundle), hashlib.sha256).hexdigest()
    return SignedPolicyBundle(bundle=bundle, signer_id=signer_id, signature=signature)


class PolicySignatureVerifier:
    def __init__(self, keys: dict[str, bytes]) -> None:
        if not keys or any(not signer_id or not isinstance(key, bytes) or len(key) < 32 for signer_id, key in keys.items()):
            raise ValueError("policy verifier requires non-empty 32-byte keys")
        self._keys = dict(keys)
        self._lock = threading.RLock()

    def verify(self, signed: SignedPolicyBundle) -> bool:
        with self._lock:
            key = self._keys.get(signed.signer_id)
        if key is None:
            return False
        expected = hmac.new(key, _signing_payload(signed.bundle), hashlib.sha256).hexdigest()
        return hmac.compare_digest(expected, signed.signature)

