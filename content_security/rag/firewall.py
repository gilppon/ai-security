from content_security.firewall import ContentFirewall
from content_security.models import ContentScanRequest, ContentScanResult, ContentSourceType, ContentType


class RAGFirewall:
    def __init__(self, content_firewall: ContentFirewall | None = None) -> None:
        self._content_firewall = content_firewall or ContentFirewall()

    def scan(
        self,
        *,
        content: str,
        content_type: ContentType = ContentType.PLAIN_TEXT,
        session_id: str | None = None,
    ) -> ContentScanResult:
        return self._content_firewall.scan(ContentScanRequest(
            content=content,
            content_type=content_type,
            source_type=ContentSourceType.RAG_DOCUMENT,
            session_id=session_id,
        ))

