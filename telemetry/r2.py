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
