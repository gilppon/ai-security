import hashlib
import time
from pathlib import Path
from unittest.mock import MagicMock

from telemetry.r2 import AsyncR2AuditDispatcher, R2WormAuditReplica


def test_async_r2_audit_dispatcher_lifecycle(tmp_path: Path):
    mock_replica = MagicMock(spec=R2WormAuditReplica)
    mock_replica.put_if_absent.return_value = True

    spool_dir = tmp_path / "audit_spool"
    dispatcher = AsyncR2AuditDispatcher(mock_replica, spool_dir=spool_dir)

    payload = '{"event": "test_event", "decision": "ALLOW"}'
    record_id = hashlib.sha256(payload.encode("utf-8")).hexdigest()

    dispatcher.record_async(record_id, payload)

    # Flush dispatcher
    success = dispatcher.flush(timeout=3.0)
    assert success is True

    # Check mock was called
    mock_replica.put_if_absent.assert_called_with(record_id, payload)

    # Verify journal file was cleaned up on success
    journal_file = spool_dir / f"{record_id}.journal"
    assert not journal_file.exists()

    dispatcher.shutdown()
