from collections.abc import Iterable

from core.risk.models import RiskContribution, RiskScore


def calculate_risk(contributions: Iterable[RiskContribution]) -> RiskScore:
    ordered = tuple(contributions)
    return RiskScore(
        total=min(100, sum(item.score for item in ordered)),
        contributions=ordered,
    )

