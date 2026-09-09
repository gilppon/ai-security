_PLACEHOLDERS = {
    "changeme",
    "example",
    "example_key",
    "insert_key_here",
    "not_a_real_secret",
    "replace_me",
    "test_token",
    "your_api_key_here",
    "your_token_here",
}


def is_placeholder(value: str) -> bool:
    normalized = value.strip().strip("'\"").casefold()
    return normalized in _PLACEHOLDERS or normalized.startswith(("example_", "test_", "your_"))
