from functools import lru_cache
from typing import Annotated

from fastapi import APIRouter, Depends, Request

from content_security.firewall import ContentFirewall
from content_security.models import ContentScanRequest, ContentScanResult
from policy.runtime import ActivePolicyDetector


@lru_cache
def _content_firewall(policy_detector: ActivePolicyDetector) -> ContentFirewall:
    return ContentFirewall(policy_detector=policy_detector)


def get_content_firewall(request: Request) -> ContentFirewall:
    return _content_firewall(request.app.state.policy_detector)


ContentFirewallDep = Annotated[ContentFirewall, Depends(get_content_firewall)]

router = APIRouter(prefix="/security/content", tags=["content-security"])


@router.post("/scan")
def scan_content(request: ContentScanRequest, firewall: ContentFirewallDep) -> ContentScanResult:
    return firewall.scan(request)
