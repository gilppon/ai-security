from core.events.types import TrustLevel
from content_security.models import ContentSourceType
from content_security.source_trust.models import SourceTrustAssessment


TRUST_RISK = {
    TrustLevel.TRUSTED: 0,
    TrustLevel.LIMITED: 10,
    TrustLevel.UNTRUSTED: 25,
    TrustLevel.UNKNOWN: 100,
}


class SourceTrustEngine:
    def assess(
        self,
        source_type: ContentSourceType,
        *,
        verified_trust: TrustLevel | None = None,
    ) -> SourceTrustAssessment:
        trust = verified_trust
        if trust is None:
            trust = TrustLevel.UNKNOWN if source_type is ContentSourceType.UNKNOWN else TrustLevel.UNTRUSTED
        return SourceTrustAssessment(
            trust_level=trust,
            risk_score=TRUST_RISK[trust],
            reason_code=f"SOURCE_{trust.value.upper()}",
        )
