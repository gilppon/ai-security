from input_security.prompt.normalizer import PromptNormalizer


def test_normalizer_applies_nfkc() -> None:
    result = PromptNormalizer().normalize("Ｉｇｎｏｒｅ")

    assert result.normalized_text == "Ignore"
    assert result.changed is True


def test_normalizer_removes_unicode_format_characters() -> None:
    result = PromptNormalizer().normalize("ig\u200bnore")

    assert result.normalized_text == "ignore"
    assert result.removed_format_characters == 1


def test_normalizer_removes_disallowed_control_characters() -> None:
    result = PromptNormalizer().normalize("safe\x00text\nnext")

    assert result.normalized_text == "safetext\nnext"
    assert result.removed_control_characters == 1


def test_normalizer_preserves_tabs_and_newlines() -> None:
    result = PromptNormalizer().normalize("a\tb\r\nc")

    assert result.normalized_text == "a\tb\nc"

