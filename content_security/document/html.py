from html.parser import HTMLParser


ACTIVE_TAGS = {"script", "iframe", "object", "embed"}
EXCLUDED_TAGS = ACTIVE_TAGS | {"style"}
BLOCK_TAGS = {"article", "br", "div", "footer", "h1", "h2", "h3", "h4", "h5", "h6", "header", "li", "main", "p", "section"}
VOID_TAGS = {"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param", "source", "track", "wbr"}
HIDDEN_STYLE_MARKERS = ("display:none", "visibility:hidden", "opacity:0", "font-size:0")


class HTMLInspectionParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.comments: list[str] = []
        self.hidden_text: list[str] = []
        self.visible_text: list[str] = []
        self.active_tags: list[str] = []
        self._suppressed: list[str | None] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        lowered_tag = tag.casefold()
        attributes = {name.casefold(): (value or "") for name, value in attrs}
        style = attributes.get("style", "").casefold().replace(" ", "")
        inherited = self._suppressed[-1] if self._suppressed else None
        reason = inherited
        if lowered_tag in EXCLUDED_TAGS:
            reason = "active" if lowered_tag in ACTIVE_TAGS else "hidden"
        elif "hidden" in attributes or any(marker in style for marker in HIDDEN_STYLE_MARKERS):
            reason = "hidden"
        if lowered_tag in ACTIVE_TAGS:
            self.active_tags.append(lowered_tag)
        if lowered_tag in BLOCK_TAGS and reason is None:
            self.visible_text.append("\n")
        if lowered_tag in VOID_TAGS:
            return
        self._suppressed.append(reason)

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.handle_starttag(tag, attrs)
        self.handle_endtag(tag)

    def handle_endtag(self, tag: str) -> None:
        reason = self._suppressed.pop() if self._suppressed else None
        if tag.casefold() in BLOCK_TAGS and reason is None:
            self.visible_text.append("\n")

    def handle_data(self, data: str) -> None:
        reason = self._suppressed[-1] if self._suppressed else None
        if reason is not None:
            self.hidden_text.append(data)
        else:
            self.visible_text.append(data)

    def handle_comment(self, data: str) -> None:
        self.comments.append(data)
