from enum import StrEnum


class TrustLevel(StrEnum):
    TRUSTED = "trusted"
    LIMITED = "limited"
    UNTRUSTED = "untrusted"
    UNKNOWN = "unknown"

