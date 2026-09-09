import re

from content_security.document.html import HTMLInspectionParser
from content_security.document.normalizer import ContentNormalizer
from content_security.models import ContentType


HTML_COMMENT = re.compile(r"<!--.*?-->", re.DOTALL)


class ContentSanitizer:
    def __init__(self, normalizer: ContentNormalizer | None = None) -> None:
        self._normalizer = normalizer or ContentNormalizer()

    def sanitize(self, content: str, content_type: ContentType) -> str:
        if content_type is ContentType.HTML:
            parser = HTMLInspectionParser()
            parser.feed(content)
            parser.close()
            visible = "".join(parser.visible_text)
            return self._normalizer.normalize(visible).normalized_text
        without_comments = (
            HTML_COMMENT.sub("", content)
            if content_type is ContentType.MARKDOWN
            else content
        )
        return self._normalizer.normalize(without_comments).normalized_text

