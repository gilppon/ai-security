import hashlib

import pytest
from botocore.exceptions import ClientError

from telemetry.r2 import R2WormAuditReplica


class _Body:
    def __init__(self, value: bytes) -> None:
        self._value = value

    def read(self) -> bytes:
        return self._value


class FakeR2Client:
    def __init__(self, existing: bytes | None = None, failure: Exception | None = None) -> None:
        self.existing = existing
        self.failure = failure
        self.put_kwargs = None

    def put_object(self, **kwargs):
        self.put_kwargs = kwargs
        if self.failure:
            raise self.failure
        return {"ETag": "test"}

    def get_object(self, **kwargs):
        return {"Body": _Body(self.existing or b"")}


def _replica(client: FakeR2Client) -> R2WormAuditReplica:
    return R2WormAuditReplica(
        endpoint_url="https://account-id.r2.cloudflarestorage.com",
        bucket="ai-security",
        access_key_id="access-id",
        secret_access_key="secret-value",
        client=client,
    )


def _record(payload: str) -> str:
    return hashlib.sha256(payload.encode()).hexdigest()


def _write_collision(code: str = "PreconditionFailed", status: int = 412) -> ClientError:
    return ClientError(
        {"Error": {"Code": code}, "ResponseMetadata": {"HTTPStatusCode": status}},
        "PutObject",
    )


def test_r2_replica_uses_content_addressed_conditional_put() -> None:
    client = FakeR2Client()
    payload = '{"event_id":"one"}'
    record_id = _record(payload)

    assert _replica(client).put_if_absent(record_id, payload) is True
    assert client.put_kwargs == {
        "Bucket": "ai-security",
        "Key": f"audit/records/{record_id}.json",
        "Body": payload.encode(),
        "ContentType": "application/json",
        "IfNoneMatch": "*",
        "Metadata": {"sha256": record_id},
    }


@pytest.mark.parametrize(
    "failure, existing, expected",
    [
        (_write_collision(), b'{"event_id":"one"}', True),
        (_write_collision(), b"different", False),
        (_write_collision("ObjectLockedByBucketPolicy", 403), b'{"event_id":"one"}', True),
    ],
)
def test_r2_replica_verifies_existing_object_after_write_collision(
    failure, existing, expected
) -> None:
    payload = '{"event_id":"one"}'
    client = FakeR2Client(existing=existing, failure=failure)

    assert _replica(client).put_if_absent(_record(payload), payload) is expected


def test_r2_replica_propagates_remote_failure() -> None:
    failure = ClientError({"Error": {"Code": "AccessDenied"}}, "PutObject")
    payload = '{"event_id":"one"}'
    with pytest.raises(ClientError):
        _replica(FakeR2Client(failure=failure)).put_if_absent(_record(payload), payload)


def test_r2_replica_rejects_invalid_endpoint_prefix_and_payload_id() -> None:
    common = dict(bucket="ai-security", access_key_id="id", secret_access_key="secret")
    with pytest.raises(ValueError):
        R2WormAuditReplica(endpoint_url="http://example.com", **common)
    with pytest.raises(ValueError):
        R2WormAuditReplica(
            endpoint_url="https://user:password@account.r2.cloudflarestorage.com", **common
        )
    with pytest.raises(ValueError):
        R2WormAuditReplica(
            endpoint_url="https://account.r2.cloudflarestorage.com", prefix="other/", **common
        )
    with pytest.raises(ValueError):
        _replica(FakeR2Client()).put_if_absent("0" * 64, "different")


def test_r2_environment_factory_reports_names_without_secret_values(monkeypatch) -> None:
    monkeypatch.setenv("AI_SECURITY_R2_SECRET_ACCESS_KEY", "must-never-appear")
    with pytest.raises(ValueError) as raised:
        R2WormAuditReplica.from_environment()
    assert "must-never-appear" not in str(raised.value)


def test_r2_replica_repr_does_not_expose_credentials() -> None:
    replica = _replica(FakeR2Client())
    assert "secret-value" not in repr(replica)
    assert "access-id" not in repr(replica)
