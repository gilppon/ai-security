import unicodedata


INJECTION_MARKERS = (
    "ignore previous instructions",
    "reveal system prompt",
    "always call this tool",
    "override tool arguments",
    "send credentials",
)


class MCPDescriptionScanner:
    def is_suspicious(self, description: str) -> bool:
        normalized = unicodedata.normalize("NFKC", description)
        if any(unicodedata.category(character) == "Cf" for character in normalized):
            return True
        comparable = normalized.casefold()
        return any(marker in comparable for marker in INJECTION_MARKERS)

