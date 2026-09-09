from functools import lru_cache
from typing import Annotated

from fastapi import APIRouter, Depends

from content_security.firewall import ContentFirewall
from content_security.models import ContentScanRequest, ContentScanResult


@lru_cache
def get_content_firewall() -> ContentFirewall:
    return ContentFirewall()


ContentFirewallDep = Annotated[ContentFirewall, Depends(get_content_firewall)]

router = APIRouter(prefix="/security/content", tags=["content-security"])


@router.post("/scan")
def scan_content(request: ContentScanRequest, firewall: ContentFirewallDep) -> ContentScanResult:
    return firewall.scan(request)

