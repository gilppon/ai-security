import re


IDENTITY_PATTERN = re.compile(r"^[A-Za-z0-9_.:-]{1,128}$")


def is_valid_identity(identity: str | None) -> bool:
    return identity is not None and IDENTITY_PATTERN.fullmatch(identity) is not None

