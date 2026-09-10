import hashlib
import json
import os
from uuid import uuid4

import pytest
from botocore.exceptions import ClientError

from telemetry.r2 import R2WormAuditReplica


REQUIRED_ENV = (
    "AI_SECURITY_R2_ENDPOINT",
    "AI_SECURITY_R2_BUCKET",
    "AI_SECURITY_R2_ACCESS_KEY_ID",
    "AI_SECURITY_R2_SECRET_ACCESS_KEY",
)


@pytest.mark.skipif(
    any(not os.environ.get(name) for name in REQUIRED_ENV),
    reason="live Cloudflare R2 credentials are not configured",
)
def test_live_r2_put_is_idempotent_and_bucket_lock_denies_delete() -> None:
    replica = R2WormAuditReplica.from_environment()
    payload = json.dumps(
        {"event_id": f"phase10-live-{uuid4()}", "purpose": "R2 durability verification"},
        separators=(",", ":"),
        sort_keys=True,
    )
    record_id = hashlib.sha256(payload.encode()).hexdigest()

    assert replica.put_if_absent(record_id, payload) is True
    assert replica.put_if_absent(record_id, payload) is True

    key = f"audit/records/{record_id}.json"
    try:
        replica._client.delete_object(  # noqa: SLF001 - live lock verification
            Bucket=os.environ["AI_SECURITY_R2_BUCKET"], Key=key
        )
    except ClientError as exc:
        status = exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
        assert status in {403, 409}
    else:
        pytest.fail("R2 bucket lock did not prevent deletion of an audit object")
