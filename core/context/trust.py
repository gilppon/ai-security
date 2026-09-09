from core.events.types import TrustLevel


TRUST_RISK: dict[TrustLevel, int] = {
    TrustLevel.TRUSTED: 0,
    TrustLevel.LIMITED: 10,
    TrustLevel.UNTRUSTED: 20,
    TrustLevel.UNKNOWN: 25,
}

